package rules

deny[msg] {
	resource := input.resource.aws_cloudfront_distribution[name]
	not resource.restrictions.geo_restrictions.restriction_type
	msg := {
		# Mandatory fields
		"publicId": "NOGEO",
		"title": "Cloudfront GEO Restrictions Disabled",
		"severity": "high",
		"msg": sprintf("input.resource.test[%s].todo", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "Restrictions for Cloudfront allow preventing of certain regions from connecting to the environment. Currently these are disabled.",
		"impact": "Leaving this setting disabled allows for threat actors in regions we don't do business with to connect to the environments unnecessarily",
		"remediation": "Set restriction_type to include a list of regions",
		"references": ["https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution"],
	}
}
