locals {
  # Tags on every resource: who, what, until when. Checked by the custom
  # policy in policy.tf and used in the day-21 review.
  tags = {
    project     = "banking-grc-controls-lab"
    environment = "lab"
    owner       = var.owner
    expires_on  = var.expires_on
    managed_by  = "terraform"
  }

  # Detection rules are read from the repository, not written here.
  # fileset() lists the sheets, yamldecode() turns each into an object.
  rules_dir = "${path.module}/../../detections/rules"
  rules = {
    for f in fileset(local.rules_dir, "DET-*.yaml") :
    trimsuffix(f, ".yaml") => yamldecode(file("${local.rules_dir}/${f}"))
  }

  # Only the rules listed in var.enabled_rules are deployed.
  enabled_rules = { for id, r in local.rules : id => r if contains(var.enabled_rules, id) }

  unknown_rules = setsubtract(toset(var.enabled_rules), toset(keys(local.rules)))
}
