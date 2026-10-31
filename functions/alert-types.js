/* E&C security log – the kinds of alert, and which ones send a phone notification.

   Shared by the server code (functions/index.js, through lib.js) and the page (index.html loads
   this file as a plain script), so the Alerts settings list and the notification check always
   agree. Every alert written to security_log/alerts carries one of these keys as `type`.

   Notification settings live in security_log/notify: { on: bool, types: { <type>: bool } }.
   A type with no setting yet uses its `on` default below (high and medium kinds on, low off). */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.EC_ALERT_TYPES = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // group: where the settings list shows it. level: what it usually is (some vary per alert).
  const TYPES = {
    // ----- E&C apps
    failed_signins:   { group: 'ec', level: 'medium', on: true,  label: 'Repeated failed sign-ins', help: '5 or more for one email, or from one IP, in 15 minutes.' },
    refused:          { group: 'ec', level: 'medium', on: true,  label: 'Account turned away by an app', help: 'A signed-in account that an app refused.' },
    new_staff:        { group: 'ec', level: 'medium', on: true,  label: 'New @ec.com account' },
    account_deleted:  { group: 'ec', level: 'high',   on: true,  label: 'Account deleted' },
    account_changed:  { group: 'ec', level: 'high',   on: true,  label: 'Account changed outside the apps', help: 'Email, custom claims, disabled, sign-in methods, password reset.' },
    new_device:       { group: 'ec', level: 'low',    on: false, label: 'Staff account on a new device' },
    access_change:    { group: 'ec', level: 'high',   on: true,  label: 'Staff list, roles or employees changed', help: 'Staff list, roles, RouteWatcher allowed users, time clock employees.' },
    settings_change:  { group: 'ec', level: 'medium', on: true,  label: 'App settings changed', help: 'RouteWatcher settings or time clock settings.' },
    no_signin_change: { group: 'ec', level: 'high',   on: true,  label: 'Database change with nobody signed in' },
    nonstaff_change:  { group: 'ec', level: 'high',   on: true,  label: 'Non-staff account changed staff data' },
    large_delete:     { group: 'ec', level: 'high',   on: true,  label: 'Large delete', help: 'One delete that removes 20 or more values.' },
    many_deletes:     { group: 'ec', level: 'high',   on: true,  label: 'Many deletes in a few minutes', help: '10 deletes by one account within 5 minutes.' },
    report_flood:     { group: 'ec', level: 'medium', on: true,  label: 'Too many reports from one place', help: 'One IP sending more than 60 sign-in reports in 10 minutes.' },
    backup_failed:    { group: 'ec', level: 'high',   on: true,  label: 'Daily database backup failed', help: 'The nightly copy of the database could not be saved.' },
    ingest_key:       { group: 'ec', level: 'high',   on: true,  label: 'Wrong key sent to the PlutoScan link', help: 'Someone guessing the key PlutoScan uses to send its log here.' },
    other:            { group: 'ec', level: 'medium', on: true,  label: 'Any other alert' },
    // ----- PlutoScan (sent by plutoscan-audit through auditIngest; the type gets a pluto_ prefix there)
    pluto_failed_signins:  { group: 'pluto', level: 'medium', on: true,  label: 'Repeated failed sign-ins' },
    pluto_course_denied:   { group: 'pluto', level: 'medium', on: true,  label: 'Repeated attempts to open the course', help: 'One IP turned away from the course 10 times in 15 minutes.' },
    pluto_purchase:        { group: 'pluto', level: 'low',    on: false, label: 'New purchase' },
    pluto_paid_removed:    { group: 'pluto', level: 'medium', on: true,  label: 'Paid access removed' },
    pluto_tampering:       { group: 'pluto', level: 'high',   on: true,  label: 'Account data tampered with', help: "Paid flag set by a user, someone else's account changed, a change with nobody signed in, unexpected data." },
    pluto_account_deleted: { group: 'pluto', level: 'high',   on: true,  label: 'Account or its data deleted' },
    pluto_account_changed: { group: 'pluto', level: 'medium', on: true,  label: 'Account changed outside the site' },
    pluto_report_flood:    { group: 'pluto', level: 'medium', on: true,  label: 'Too many reports from one place' },
    pluto_other:           { group: 'pluto', level: 'medium', on: true,  label: 'Any other PlutoScan alert' }
  };
  const GROUPS = { ec: 'E&C apps', pluto: 'PlutoScan' };

  /** The type key of an alert; old alerts and unknown kinds count as "other". */
  function typeOf(alert) {
    const t = alert && alert.type;
    if (TYPES[t]) return t;
    return /^plutoscan/.test(String((alert && alert.src) || '')) ? 'pluto_other' : 'other';
  }

  /** Whether an alert should send a phone notification under the saved settings (null = never saved). */
  function wantsPush(alert, notify) {
    const n = notify || {};
    if (n.on === false) return false;
    const t = typeOf(alert);
    const set = n.types && n.types[t];
    return typeof set === 'boolean' ? set : TYPES[t].on;
  }

  return { TYPES, GROUPS, typeOf, wantsPush };
});
