package rules

deny[msg] {
	resource := input.resource.aws_s3_bucket[name]
	not resource.tags
	msg := {
		# Mandatory fields
		"publicId": "S3-TAG",
		"title": "Missing S3 Tags",
		"severity": "low",
		"msg": sprintf("input.resource.test[%s].todo", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "",
		"impact": "",
		"remediation": "",
		"references": [],
	}
}
