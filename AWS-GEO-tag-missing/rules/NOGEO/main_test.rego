package rules

import data.lib
import data.lib.testing

test_NOGEO {
	# array containing test cases where the rule is allowed
	allowed_test_cases := [{
		"want_msgs": [],
		"fixture": "allowed.json.tfplan",
	}]

	# array containing cases where the rule is denied
	denied_test_cases := [{
		"want_msgs": ["input.resource.test[denied].todo"], # verifies that the correct msg is returned by the denied rule
		"fixture": "denied.json.tfplan",
	}]

	test_cases := array.concat(allowed_test_cases, denied_test_cases)
	testing.evaluate_test_cases("NOGEO", "./rules/NOGEO/fixtures", test_cases)
}
