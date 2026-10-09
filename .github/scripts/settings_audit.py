#!/usr/bin/env python3
"""Read-only GitHub declaration audit. Exit: 0 match, 1 drift, 2 schema, 3 unknown."""
import argparse
import json
import re
import subprocess
import sys

REST = dict.fromkeys('has_issues has_projects has_wiki has_discussions is_template web_commit_signoff_required allow_forking'.split(), bool)
GRAPHQL = dict.fromkeys('mergeCommitAllowed squashMergeAllowed rebaseMergeAllowed autoMergeAllowed allowUpdateBranch deleteBranchOnMerge hasSponsorshipsEnabled'.split(), bool)
GRAPHQL.update({k: str for k in 'squashMergeCommitTitle squashMergeCommitMessage mergeCommitTitle mergeCommitMessage issueCreationPolicy pullRequestCreationPolicy'.split()})
ENUMS = {'squashMergeCommitTitle': ['PR_TITLE','COMMIT_OR_PR_TITLE'], 'squashMergeCommitMessage': ['PR_BODY','COMMIT_MESSAGES','BLANK'], 'mergeCommitTitle': ['PR_TITLE','MERGE_MESSAGE'], 'mergeCommitMessage': ['PR_BODY','PR_TITLE','BLANK'], 'issueCreationPolicy': ['ALL','COLLABORATORS_ONLY'], 'pullRequestCreationPolicy': ['ALL','COLLABORATORS_ONLY']}
RULE_FIELDS = {'name':str,'target':str,'enforcement':str,'conditions':dict,'rules':list,'bypass_actors':list}
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
        if type(item) is not fields[key] or (key in ENUMS and item not in ENUMS[key]):
            raise ValueError(path + '.' + key + ': invalid value/type')


def gh(host, *args, raw=False):
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
    if actual is MISSING or actual is None:
        findings.append({'path':path,'status':'unknown','expected':wanted})
    elif isinstance(wanted, dict):
        if not isinstance(actual, dict):
            findings.append({'path':path,'status':'unknown','reason':'response shape'})
        else:
            for key, value in wanted.items():
                compare(value, actual.get(key, MISSING), path + '.' + key, findings)
    elif isinstance(wanted, list):
        if not isinstance(actual, list):
            findings.append({'path':path,'status':'unknown','reason':'response shape'})
            return
        remaining = list(actual)
        for index, value in enumerate(wanted):
            keys = [k for k in ('type','context','actor_type','actor_id') if isinstance(value, dict) and k in value]
            candidates = [i for i, item in enumerate(remaining) if (all(isinstance(item, dict) and item.get(k) == value[k] for k in keys) if keys else item == value)]
            if len(candidates) == 1:
                compare(value, remaining.pop(candidates[0]), f'{path}[{index}]', findings)
            else:
                findings.append({'path':f'{path}[{index}]','status':'drift','expected':value,'reason':'missing or ambiguous array entry'})
        if remaining:
            findings.append({'path':path,'status':'drift','actual_extra':remaining})
    else:
        findings.append({'path':path,'status':'match' if type(actual) is type(wanted) and actual == wanted else 'drift','expected':wanted,'actual':actual})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--repo', required=True, help='literal OWNER/REPO')
    parser.add_argument('--settings', required=True, help='JSON containing rest/graphql objects')
    parser.add_argument('--ruleset', help='one ruleset JSON; match name + target')
    parser.add_argument('--compare-bypass', action='store_true', help='admin-visible only; never proves effective access')
    args = parser.parse_args()
    findings = []
    try:
        if not re.fullmatch(r'[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*', args.host) or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9_.-]+', args.repo) or args.repo.split('/')[-1] in ('.','..'):
            raise ValueError('host/repo format invalid; use HOST and OWNER/REPO separately')
        wanted = load(args.settings)
        validate(wanted, {'rest':dict,'graphql':dict}, 'settings')
        if not wanted or not any(wanted.values()):
            raise ValueError('settings must declare at least one supported field')
        for section, fields in [('rest', REST), ('graphql', GRAPHQL)]:
            validate(wanted.get(section, {}), fields, section)
        rules = load(args.ruleset) if args.ruleset else None
        if rules is not None:
            validate(rules, RULE_FIELDS, 'ruleset')
            if not rules.get('name') or rules.get('target') not in ('branch','tag'):
                raise ValueError('ruleset requires name and branch/tag target')
            if 'enforcement' in rules and rules['enforcement'] not in ('active','disabled','evaluate'):
                raise ValueError('ruleset enforcement invalid')
            for rule in rules.get('rules', []):
                validate(rule, {'type':str,'parameters':dict}, 'ruleset.rules')
                if not rule.get('type'):
                    raise ValueError('rule requires type')
            for actor in rules.get('bypass_actors', []):
                validate(actor, {'actor_id':int,'actor_type':str,'bypass_mode':str}, 'bypass_actors')
        gh(args.host, 'auth','status','--hostname',args.host, raw=True)
        view = gh(args.host,'repo','view',args.host+'/'+args.repo,'--json','nameWithOwner,defaultBranchRef')
        actual = gh(args.host,'api','--hostname',args.host,'--method','GET','repos/'+args.repo)
        if not isinstance(view,dict) or not isinstance(actual,dict) or view.get('nameWithOwner','').casefold() != args.repo.casefold() or actual.get('full_name','').casefold() != args.repo.casefold():
            raise Unknown('exact-target preflight identity mismatch; remote audit blocked')
        compare(wanted.get('rest',{}),actual,'rest',findings)
        if wanted.get('graphql'):
            owner, name = args.repo.split('/')
            query = 'query($owner:String!,$name:String!){repository(owner:$owner,name:$name){'+' '.join(wanted['graphql'])+'}}'
            try:
                response = gh(args.host,'api','--hostname',args.host,'graphql','-f','query='+query,'-f','owner='+owner,'-f','name='+name)
                data = response.get('data') or {}
                compare(wanted['graphql'],data.get('repository'), 'graphql',findings)
                if response.get('errors'):
                    findings.append({'path':'graphql','status':'unknown','reason':'GraphQL errors; check schema/permissions'})
            except Unknown as error:
                findings.append({'path':'graphql','status':'unknown','reason':str(error)})
        if rules is not None:
            try:
                pages = gh(args.host,'api','--hostname',args.host,'--method','GET','repos/'+args.repo+'/rulesets?includes_parents=true&per_page=100','--paginate','--slurp')
                matches = [r for page in pages for r in page if r.get('name') == rules['name'] and r.get('target') == rules['target']]
                if len(matches) > 1:
                    raise Unknown('ambiguous matching rulesets; inspect repository and inherited policy')
                if not matches:
                    findings.append({'path':'ruleset','status':'drift','reason':'no matching name + target'})
                else:
                    detail = gh(args.host,'api','--hostname',args.host,'--method','GET',f"repos/{args.repo}/rulesets/{matches[0]['id']}")
                    selected = dict(rules)
                    if 'bypass_actors' in selected and not args.compare_bypass:
                        selected.pop('bypass_actors')
                        findings.append({'path':'ruleset.bypass_actors','status':'unknown','reason':'comparison opt-in requires independently verified admin visibility'})
                    compare(selected,detail,'ruleset',findings)
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
    print(json.dumps({'host':args.host,'repo':args.repo,'status':status,'coverage':{'ruleset':'selected; declaration comparison only, not effective enforcement' if args.ruleset else 'not_requested; no protection compliance claim','bypass':'opt-in; admin-visible declared actors only' if args.compare_bypass else 'not compared; CI visibility not guaranteed','identity':'current gh credential; operator and CI coverage differ'},'findings':findings}))
    if code:
        print(f'{status}: inspect JSON findings; correct declarations/access or approve drift remediation. No changes applied.',file=sys.stderr)
    return code

if __name__ == '__main__':
    sys.exit(main())