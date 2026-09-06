
import grp
import pwd

NOT_LOGIN = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "",
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
    

