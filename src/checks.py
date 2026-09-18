
import grp
import pwd

NOT_LOGIN = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "",
}

SENSITIVE_GROUPS = {
    "sudo" : "WARNING",
    "wheel" : "WARNING",
    "adm"   : "IMFO",
    "docker" : "CRITICAL",
}

def check_user() -> dict :

    findings = []

    for user in pwd.getpwall():
        can_login = user.pw_shell not in NOT_LOGIN
        is_root = user.pw_gid == 0

        if is_root and user.pw_name != "root":
            severity = "CRITICAL"
            message = f"Compte UID 0 autre que root : {user.pw_name}"
        elif can_login:
            severity = "INFO"
            message = f"Compte de connexion actif : {user.pw_name}"
        else:
            continue

        findings.append(
            {
                "severity": severity,
                "message" : message,
                "user": user.pw_name,
                "directory" : user.pw_dir,
                "uid" : user.pw_gid,
                "shell" : user.pw_shell
            }
        )

    return {
        "check" : "user",
        "status" : "ok",
        "finding" : findings,
    }
    

def check_sudo_groups() -> dict :
    """Signale les membres des groupes conférant des privilèges élevés."""
    findings = []
    for group in grp.getgrall():
        severity = SENSITIVE_GROUPS.get(goupe.gr_name)
        if severity is None:
            continue

        for member in group.gr_mem:
            findings.append({
                "severity" : severity,
                "message" : f"{member} est menbre du groupe '{group.gr_name}'",
                "user" : member,
                "group" : group.gr_name,
       })
return {
    "check" : "sudo_groups",
    "status" : "OK",
    "findings" : findings,

}
