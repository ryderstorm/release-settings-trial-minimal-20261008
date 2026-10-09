#!/usr/bin/env python3
"""Read-only GitHub declaration audit. Exit: 0 match, 1 drift, 2 schema, 3 unknown."""
import argparse
import json
import re
import subprocess
import sys
from typing import Any

REST: dict[str, type] = dict.fromkeys('has_issues has_projects has_wiki has_discussions is_template web_commit_signoff_required allow_forking'.split(), bool)
GRAPHQL: dict[str, type] = dict.fromkeys('mergeCommitAllowed squashMergeAllowed rebaseMergeAllowed autoMergeAllowed allowUpdateBranch deleteBranchOnMerge hasSponsorshipsEnabled'.split(), bool)
GRAPHQL.update({k: str for k in 'squashMergeCommitTitle squashMergeCommitMessage mergeCommitTitle mergeCommitMessage issueCreationPolicy pullRequestCreationPolicy'.split()})
ENUMS = {'squashMergeCommitTitle': ['PR_TITLE','COMMIT_OR_PR_TITLE'], 'squashMergeCommitMessage': ['PR_BODY','COMMIT_MESSAGES','BLANK'], 'mergeCommitTitle': ['PR_TITLE','MERGE_MESSAGE'], 'mergeCommitMessage': ['PR_BODY','PR_TITLE','BLANK'], 'issueCreationPolicy': ['ALL','COLLABORATORS_ONLY'], 'pullRequestCreationPolicy': ['ALL','COLLABORATORS_ONLY']}
RULE_FIELDS = {'name':str,'target':str,'enforcement':str,'conditions':dict,'rules':list,'bypass_actors':list}
REST['default_branch'] = str
MISSING = object()

class Unknown(Exception):
    pass


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    with open(path, encoding='utf-8') as stream:
        return json.load(stream, object_pairs_hook=unique)


def validate(value, fields, path):
    if not isinstance(value, dict) or set(value) - set(fields):
        raise ValueError(path + ': expected object with supported fields ' + ', '.join(fields))
    for key, item in value.items():
        if type(item) is not fields[key] or (key in ENUMS and item not in ENUMS[key]) or (key == 'default_branch' and not item.strip()):
            raise ValueError(path + '.' + key + ': invalid value/type')


def validate_nested(rules):
    # Limited comparison schema, not an exhaustive GitHub apply-payload validator.
    ref = rules.get('conditions', {}).get('ref_name', MISSING)
    if ref is not MISSING:
        if not isinstance(ref, dict):
            raise ValueError('conditions.ref_name must be an object')
        for key in ('include', 'exclude'):
            if key in ref and (not isinstance(ref[key], list) or any(type(v) is not str for v in ref[key])):
                raise ValueError('conditions.ref_name.' + key + ' must be a string array')
    booleans = {'dismiss_stale_reviews_on_push', 'require_code_owner_review',
                'require_last_push_approval', 'required_review_thread_resolution',
                'strict_required_status_checks_policy', 'do_not_enforce_on_create',
                'automatic_copilot_code_review_enabled', 'update', 'non_fast_forward'}
    for rule in rules.get('rules', []):
        validate(rule, {'type': str, 'parameters': dict}, 'ruleset.rules')
        params = rule.get('parameters', {})
        for key in booleans & params.keys():
            if type(params[key]) is not bool:
                raise ValueError('parameters.' + key + ' must be boolean')
        if 'required_approving_review_count' in params:
            count = params['required_approving_review_count']
            if type(count) is not int or count < 0:
                raise ValueError('required_approving_review_count must be a nonnegative integer')
        if 'required_status_checks' in params:
            checks = params['required_status_checks']
            if not isinstance(checks, list):
                raise ValueError('required_status_checks must be an array')
            for check in checks:
                if not isinstance(check, dict) or type(check.get('context')) is not str:
                    raise ValueError('required_status_checks entry requires string context')
                integration = check.get('integration_id')
                if integration is not None and (type(integration) is not int or integration <= 0):
                    raise ValueError('integration_id must be positive integer or null')


def gh(host: str, *args: str, raw: bool = False) -> Any:
    try:
        proc = subprocess.run(['gh', *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Unknown('gh unavailable or timed out; check installation/network') from error
    if proc.returncode:
        # Never echo provider stderr: it may contain credentials or source data.
        kind = 'capability restriction' if 'Upgrade to GitHub Pro' in proc.stderr else 'permission' if '403' in proc.stderr else 'not-found/access' if '404' in proc.stderr else 'authentication' if args[0] == 'auth' else 'API/network'
        raise Unknown(f'{kind}: gh {args[0]} failed (exit {proc.returncode}); verify {host} target access and endpoint permissions')
    if raw:
        return None
    try:
        return json.loads(proc.stdout)
    except ValueError as error:
        raise Unknown('gh returned invalid JSON') from error


def compare(wanted, actual, path, findings):
    if actual is MISSING or (actual is None and wanted is not None):
        findings.append({'path':path,'status':'unknown','expected':wanted})
    elif isinstance(wanted, dict):
        if not isinstance(actual, dict):
            findings.append({'path':path,'status':'drift','expected':wanted,'actual':actual,'reason':'response type differs'})
        else:
            for key, value in wanted.items():
                compare(value, actual.get(key, MISSING), path + '.' + key, findings)
    elif isinstance(wanted, list):
        if not isinstance(actual, list):
            findings.append({'path':path,'status':'drift','expected':wanted,'actual':actual,'reason':'response type differs'})
            return
        # Small evidence arrays: exact edges first, then non-drift potential edges.
        probes = []
        for index, value in enumerate(wanted):
            row = []
            for item in actual:
                probe = []
                compare(value, item, f'{path}[{index}]', probe)
                row.append(probe)
            probes.append(row)
        exact = [[i for i, probe in enumerate(row) if all(f['status'] == 'match' for f in probe)] for row in probes]
        potential = [[i for i, probe in enumerate(row) if not any(f['status'] == 'drift' for f in probe)] for row in probes]
        assigned = {}
        def assign(index, seen, edges):
            for candidate in edges[index]:
                if candidate in seen:
                    continue
                seen.add(candidate)
                if candidate not in assigned or assign(assigned[candidate], seen, edges):
                    assigned[candidate] = index
                    return True
            return False
        for index in range(len(wanted)):
            assign(index, set(), exact)
        for index in range(len(wanted)):
            if index not in assigned.values():
                assign(index, set(), potential)
        for index, value in enumerate(wanted):
            if index in assigned.values():
                continue
            for candidate, item in enumerate(actual):
                if candidate in assigned or not isinstance(value, dict) or not isinstance(item, dict):
                    continue
                identity = next((key for key in ('type', 'context', 'actor_type') if key in value), None)
                if identity is not None and type(item.get(identity)) is type(value[identity]) and item.get(identity) == value[identity]:
                    assigned[candidate] = index
                    break
            else:
                findings.append({'path':f'{path}[{index}]','status':'drift','expected':value,'reason':'missing matching array entry'})
        for candidate, index in sorted(assigned.items(), key=lambda entry: entry[1]):
            findings.extend(probes[index][candidate])
        remaining = [item for index, item in enumerate(actual) if index not in assigned]
        if remaining:
            findings.append({'path':path,'status':'drift','actual_extra':remaining})
    else:
        findings.append({'path':path,'status':'match' if type(actual) is type(wanted) and actual == wanted else 'drift','expected':wanted,'actual':actual})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--repo', required=True, help='literal OWNER/REPO')
    parser.add_argument('--settings', help='JSON containing rest/graphql objects')
    parser.add_argument('--ruleset', help='one ruleset JSON; match name + target')
    parser.add_argument('--compare-bypass', action='store_true', help='admin-visible only; never proves effective access')
    parser.add_argument('--preflight', action='store_true', help='exact-target access evidence only; no declaration required')
    parser.add_argument('--scope', choices=('ci','operator'), default='operator', help='ci excludes bypass comparison explicitly; operator remains conservative')
    args = parser.parse_args()
    findings = []
    preflight = {'status':'not collected'}
    collected = False
    rules_collected = False
    rules_compared = False
    try:
        if not re.fullmatch(r'[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*', args.host) or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9_.-]+', args.repo) or args.repo.split('/')[-1] in ('.','..'):
            raise ValueError('host/repo format invalid; use HOST and OWNER/REPO separately')
        if not args.settings and not args.preflight:
            raise ValueError('--settings required unless --preflight is selected')
        if args.scope == 'ci' and args.compare_bypass:
            raise ValueError('--compare-bypass is operator-only; CI exclusion cannot verify bypass')
        wanted = {} if args.preflight else load(args.settings)
        validate(wanted, {'rest':dict,'graphql':dict}, 'settings')
        if not args.preflight and (not wanted or not any(wanted.values())):
            raise ValueError('settings must declare at least one supported field')
        for section, fields in [('rest', REST), ('graphql', GRAPHQL)]:
            validate(wanted.get(section, {}), fields, section)
        rules = load(args.ruleset) if args.ruleset else None
        if args.ruleset:
            if not isinstance(rules, dict):
                raise ValueError('ruleset must be a non-null object')
            validate(rules, RULE_FIELDS, 'ruleset')
            if not rules.get('name') or rules.get('target') not in ('branch','tag'):
                raise ValueError('ruleset requires name and branch/tag target')
            if 'enforcement' in rules and rules['enforcement'] not in ('active','disabled','evaluate'):
                raise ValueError('ruleset enforcement invalid')
            validate_nested(rules)
            for rule in rules.get('rules', []):
                validate(rule, {'type':str,'parameters':dict}, 'ruleset.rules')
                if not rule.get('type'):
                    raise ValueError('rule requires type')
            for actor in rules.get('bypass_actors', []):
                if not isinstance(actor,dict) or set(actor) != {'actor_id','actor_type','bypass_mode'}:
                    raise ValueError('bypass actor requires exactly actor_id, actor_type, bypass_mode')
                if actor['actor_type'] not in ('OrganizationAdmin','RepositoryRole','Team','Integration','DeployKey') or actor['bypass_mode'] not in ('always','pull_request','exempt'):
                    raise ValueError('unsupported bypass actor type/mode')
                if not (actor['actor_type'] == 'OrganizationAdmin' and actor['actor_id'] is None) and (type(actor['actor_id']) is not int or actor['actor_id'] <= 0):
                    raise ValueError('bypass actor_id must be a positive integer or null for OrganizationAdmin')
        if args.preflight:
            rules = None
        gh(args.host, 'auth','status','--hostname',args.host, raw=True)
        view = gh(args.host,'repo','view',args.host+'/'+args.repo,'--json','nameWithOwner,defaultBranchRef')
        actual = gh(args.host,'api','--hostname',args.host,'--method','GET','repos/'+args.repo)
        if not isinstance(view,dict) or not isinstance(actual,dict) or view.get('nameWithOwner','').casefold() != args.repo.casefold() or actual.get('full_name','').casefold() != args.repo.casefold():
            raise Unknown('exact-target preflight identity mismatch; remote audit blocked')
        preflight = {'status':'verified','nameWithOwner':view['nameWithOwner'],'defaultBranchRef':view.get('defaultBranchRef'),'full_name':actual['full_name']}
        collected = not args.preflight
        compare(wanted.get('rest',{}),actual,'rest',findings)
        if wanted.get('graphql'):
            owner, name = args.repo.split('/')
            query = 'query($owner:String!,$name:String!){repository(owner:$owner,name:$name){'+' '.join(wanted['graphql'])+'}}'
            try:
                response = gh(args.host,'api','--hostname',args.host,'graphql','-f','query='+query,'-f','owner='+owner,'-f','name='+name)
                if not isinstance(response,dict) or not isinstance(response.get('data'),dict):
                    raise Unknown('invalid GraphQL response shape')
                data = response['data']
                if data.get('repository') is not None and not isinstance(data.get('repository'), dict):
                    raise Unknown('invalid GraphQL repository response shape')
                compare(wanted['graphql'],data.get('repository'), 'graphql',findings)
                if response.get('errors'):
                    findings.append({'path':'graphql','status':'unknown','reason':'GraphQL errors; check schema/permissions'})
            except Unknown as error:
                findings.append({'path':'graphql','status':'unknown','reason':str(error)})
        if rules is not None:
            try:
                pages = gh(args.host,'api','--hostname',args.host,'--method','GET','repos/'+args.repo+'/rulesets?includes_parents=true&per_page=100','--paginate','--slurp')
                if not isinstance(pages, list) or any(not isinstance(page, list) or any(not isinstance(entry, dict) for entry in page) for page in pages):
                    raise Unknown('invalid ruleset list response shape')
                rules_collected = True
                matches = [r for page in pages for r in page if r.get('name') == rules['name'] and r.get('target') == rules['target']]
                if len(matches) > 1:
                    raise Unknown('ambiguous matching rulesets; inspect repository and inherited policy')
                if not matches:
                    findings.append({'path':'ruleset','status':'drift','reason':'no matching name + target'})
                else:
                    detail = gh(args.host,'api','--hostname',args.host,'--method','GET',f"repos/{args.repo}/rulesets/{matches[0]['id']}")
                    if detail is not None and not isinstance(detail, dict):
                        raise Unknown('invalid ruleset detail response shape')
                    selected = dict(rules)
                    if 'bypass_actors' in selected and not args.compare_bypass:
                        selected.pop('bypass_actors')
                        findings.append({'path':'ruleset.bypass_actors','status':'excluded' if args.scope == 'ci' else 'unknown','reason':'EXCLUDED from CI comparison; UNVERIFIED admin policy' if args.scope == 'ci' else 'comparison opt-in requires independently verified admin visibility'})
                    compare(selected,detail,'ruleset',findings)
                    rules_compared = True
            except (Unknown, KeyError, TypeError) as error:
                findings.append({'path':'ruleset','status':'unknown','reason':str(error) if isinstance(error,Unknown) else 'invalid ruleset API response'})
        status = 'unknown' if any(f['status']=='unknown' for f in findings) else 'drift' if any(f['status']=='drift' for f in findings) else 'match'
        code = {'match':0,'drift':1,'unknown':3}[status]
    except (ValueError, OSError) as error:
        status, code = 'schema_error', 2
        findings.append({'path':'input','status':status,'reason':str(error)})
    except (Unknown, TypeError, AttributeError) as error:
        status, code = 'unknown', 3
        findings.append({'path':'collection','status':status,'reason':str(error) if isinstance(error,Unknown) else 'invalid API response shape'})
    coverage = {
        'settings':'collected; declared fields only' if collected else 'not collected; preflight only' if args.preflight and preflight['status'] == 'verified' else 'not collected',
        'ruleset':'selected; declaration comparison only, not effective enforcement' if rules_compared else 'list collected; selected policy comparison incomplete; no enforcement claim' if rules_collected else 'not collected; no protection compliance claim',
        'bypass':'EXCLUDED from CI; UNVERIFIED; authoritative desired policy unchanged' if args.scope == 'ci' else 'opt-in; admin-visible declared actors only' if args.compare_bypass else 'not compared; admin visibility not guaranteed',
        'full_policy_verified':False,
        'identity':'current gh credential; operator and CI coverage differ',
    }
    print(json.dumps({'host':args.host,'repo':args.repo,'scope':args.scope,'status':status,'preflight':preflight,'coverage':coverage,'findings':findings}))
    if code:
        print(f'{status}: inspect JSON findings; correct declarations/access or approve drift remediation. No changes applied.',file=sys.stderr)
    return code

if __name__ == '__main__':
    sys.exit(main())