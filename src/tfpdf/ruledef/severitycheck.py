import boto3
from botocore.exceptions import ClientError

# -----------------------------------------------------------
# Verifie l'etat des ressources pour pouvoir ajuster la severity
# Selon l'importance de la ressource la severity augmente
# -----------------------------------------------------------
s3 = None
AWS_OK = None


# A appeler une fois au debut d'un scan, jamais par decouverte : chaque appel
# est un aller-retour vers STS et un client neuf. Le resultat est garde dans
# AWS_OK, que les verifications lisent. Tant que personne ne l'a appelee,
# AWS_OK vaut None : les verifications rendent la severity inchangee, ce qui
# est le bon defaut.
def available_context() -> bool:
    global s3, AWS_OK
    try:
        boto3.client("sts").get_caller_identity()
        s3 = boto3.client("s3")
        AWS_OK = True
    except Exception:
        AWS_OK = False
    return AWS_OK


def s3_force_destroy_severity_check(severity: str, bucket: str) -> str:
    # `s3 is None` en plus de AWS_OK : les deux sont poses ensemble par
    # available_context, mais rien dans le type ne le dit, et une verification
    # appelee sans sonde prealable planterait au lieu de rendre la severity.
    if not AWS_OK or s3 is None:
        return severity

    objects_counts = 0
    try:
        info = s3.list_objects_v2(Bucket=bucket)
    except ClientError as error:
        code = error.response["Error"]["Code"]
        if code == "NoSuchBucket":
            severity = "low"
            return severity
        return severity

    for objects in info.get("Contents", []):
        if objects["Key"]:
            objects_counts += 1

    if info.get("Contents", []) == []:
        severity = "low"
        return severity
    if objects_counts >= 1:
        return "critical"

    return severity
