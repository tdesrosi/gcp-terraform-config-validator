#
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package templates.gcp.TFGCPIAMAllowedPolicyMemberDomainsConstraintV2

import data.validator.gcp.lib as lib

deny[{
	"msg": message,
	"details": metadata,
}] {
	# NOTE: For Terraform review object, the following schema is followed:
	# review: {
	# 	change: {
	# 		actions: ["create"],
	# 		after: {
	#			condition: []
	#			members: []
	#			project:
	# 			role: 
	# 		}
	# 	},
	# 	mode:
	# 	name: 
	# 	provider_name:
	# 	type:
	# }

	# input.constraint is the same for TF validate as CAI validate (comes from the constraint.yaml)
	constraint := input.constraint
	lib.get_constraint_params(constraint, params)

	# Use input.review for TF changes (see schema above)
	resource := input.review[_]

	resource.type == "google_project_iam_binding"

	unique_members := {m | m = resource.change.after.members[_]}
	member_type_allowlist := lib.get_default(params, "member_type_allowlist", ["projectOwner", "projectEditor", "projectViewer"])

	members_to_check := [m | m = unique_members[_]; not starts_with_allowlisted_type(member_type_allowlist, m)]

	member := members_to_check[_]

	allow_sub_domains := lib.get_default(params, "allow_sub_domains", true)

	trace(sprintf("result of no match fn: %v", [no_match(allow_sub_domains, params.domains, members_to_check[_])]))

	no_match(allow_sub_domains, params.domains, member)

	trace(sprintf("IAM policy for %v contains member from unexpected domain: %v", [resource.title, member]))

	message := sprintf("IAM policy for %v contains member from unexpected domain: %v", [resource.title, member])

	metadata := {"resource": resource.title, "member": member}

	trace(sprintf("Metadata: %v", [metadata]))
}

no_match(allow_sub_domains, domains, member) {
	allow_sub_domains == true
	matched_domains := [m | m = member; re_match(sprintf("[:@.]%v$", [domains[_]]), member)]
	trace(sprintf("matched domains, %v", [count(matched_domains)]))
	count(matched_domains) == 0
}

no_match(allow_sub_domains, domains, member) {
	allow_sub_domains == false
	matched_domains := [m | m = member; re_match(sprintf("[:@]%v$", [domains[_]]), member)]
	trace(sprintf("matched domains, %v", [matched_domains]))
	count(matched_domains) == 0
}

starts_with_allowlisted_type(allowlist, member) {
	member_type := allowlist[_]
	startswith(member, sprintf("%v:", [member_type]))
}
