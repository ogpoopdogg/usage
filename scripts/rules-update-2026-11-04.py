#!/usr/bin/env python3
"""Database rules changes from the 2026-11-04 security review (fixes 6 and 8).

Reads the live rules (or a file), makes only these changes, and writes the result:
  1. celeste@ec.com is no longer an admin in the rules (she has no account; whoever signed up
     first as her would have become a time clock and garage admin).
  2. Areas nothing uses any more can't be written by anyone: the old command-center areas,
     user_orders, address_lookup_delivery, delivery_lookup. Reading is unchanged (they're empty).
  3. users/<uid> only takes the fields Request Pickup writes (company_id, theme, profile), with sizes.
  4. Developer notes move to their own area, developer_notes/<id>, with sizes; developer/<anything>
     is no longer writable except Route Planner (developer/route_planner, staff, as before) and
     RouteWatcher's refused sign-in log (developer/login_refusals), which becomes add-only.

Usage: python3 scripts/rules-update-2026-11-04.py --in CURRENT.json --out NEW.json
scripts/setup-security-fixes.sh downloads the live rules, runs this, and deploys the result.
"""
import argparse, copy, json

STAFF = "auth != null && root.child('staff').child(auth.uid).val() == true"
CELESTE = " || auth.token.email.toLowerCase() === 'celeste@ec.com'"
LOCK = ['drivers', 'driver_locations', 'command_tokens', 'driver_geofences', 'driver_zones',
        'recurring_schedules', 'jobs', 'user_orders', 'address_lookup_delivery', 'delivery_lookup']


def strip_comments(text):
    out, i, in_str = [], 0, False
    while i < len(text):
        c = text[i]
        if in_str:
            out.append(c)
            if c == '\\':
                out.append(text[i + 1]); i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True; out.append(c)
        elif text.startswith('//', i):
            while i < len(text) and text[i] != '\n': i += 1
            continue
        elif text.startswith('/*', i):
            i = text.index('*/', i) + 2; continue
        else:
            out.append(c)
        i += 1
    return ''.join(out)


def drop_writes(node):
    """Removes every .write in a subtree, so nothing under it can be written (rules deny by default)."""
    if isinstance(node, dict):
        node.pop('.write', None)
        for k, v in node.items():
            if not k.startswith('.'): drop_writes(v)


def patch(rules):
    r = copy.deepcopy(rules)
    root = r['rules']
    notes = []

    # 1. celeste
    text = json.dumps(r)
    n = text.count(CELESTE)
    r = json.loads(text.replace(CELESTE, ''))
    root = r['rules']
    if 'celeste@ec.com' in json.dumps(r):
        raise SystemExit('celeste@ec.com still appears in a form this script does not know; nothing changed')
    notes.append('removed celeste@ec.com as an admin (%d places)' % n)

    # 2. lock unused areas
    for area in LOCK:
        if area in root:
            drop_writes(root[area])
            root[area]['.write'] = False
            notes.append('locked %s' % area)

    # 3. users/<uid>: only the fields Request Pickup writes
    u = root.setdefault('users', {}).setdefault('$uid', {})
    u['profile'] = {
        'name': {'.validate': 'newData.isString() && newData.val().length <= 80'},
        'phone': {'.validate': 'newData.isString() && newData.val().length <= 30'},
        '$other': {'.validate': False}
    }
    u['$other'] = {'.validate': False}
    notes.append('users/<uid>: only company_id, theme, profile {name, phone}')

    # 4. developer notes
    dev = root.setdefault('developer', {})
    if '$note_id' in dev:
        del dev['$note_id']
        notes.append('developer/<anything> is no longer writable, except route_planner (staff, as before)')
    # Route Planner had no rule of its own and was written through developer/$note_id
    rp = dev.setdefault('route_planner', {})
    if '.write' not in rp:
        rp['.write'] = STAFF
    dev['login_refusals'] = {'$id': {
        '.write': STAFF + ' && !data.exists() && newData.exists()',
        '.validate': "newData.hasChildren(['at', 'why'])",
        'at': {'.validate': 'newData.isString() && newData.val().length <= 40'},
        'email': {'.validate': 'newData.isString() && newData.val().length <= 200'},
        'why': {'.validate': 'newData.isString() && newData.val().length <= 300'},
        'page': {'.validate': 'newData.isString() && newData.val().length <= 200'},
        'db': {'.validate': 'newData.isString() && newData.val().length <= 300'},
        'device': {'.validate': 'newData.isString() && newData.val().length <= 200'},
        '$other': {'.validate': False}
    }}
    root['developer_notes'] = {
        '.read': STAFF,
        '$id': {
            # Staff add notes; only the admin changes a status or deletes one
            '.write': STAFF + " && (!data.exists() || auth.token.email.toLowerCase() === 'justin@ec.com')",
            '.validate': "$id.matches(/^[A-Za-z0-9_-]{1,40}$/) && newData.hasChildren(['text', 'user', 'timestamp'])",
            # The editor's HTML; pasted pictures are stored inside it, hence the room
            'text': {'.validate': 'newData.isString() && newData.val().length > 0 && newData.val().length <= 200000'},
            'user': {'.validate': 'newData.isString() && newData.val().length <= 60'},
            'date': {'.validate': 'newData.isString() && newData.val().length <= 60'},
            'timestamp': {'.validate': 'newData.isNumber() && (data.exists() ? newData.val() === data.val() : newData.val() === now)'},
            'app': {'.validate': 'newData.isString() && newData.val().length <= 40'},
            'statusText': {'.validate': 'newData.isString() && newData.val().length <= 100'},
            '$other': {'.validate': False}
        }
    }
    notes.append('developer notes moved to developer_notes/<id> (staff add, admin edits); developer/login_refusals add-only')
    return r, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--in', dest='src', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    raw = json.load(open(a.src))
    # firebase database:get of security_log/rules_watch/text gives the rules as one JSON string
    text = raw if isinstance(raw, str) else json.dumps(raw)
    new, notes = patch(json.loads(strip_comments(text)))
    open(a.out, 'w').write(json.dumps(new, indent=2) + '\n')
    print('Wrote ' + a.out)
    for n in notes: print(' - ' + n)


if __name__ == '__main__':
    main()
