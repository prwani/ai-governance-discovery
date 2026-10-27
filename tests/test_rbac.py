import unittest
from urllib.parse import parse_qs, urlsplit

from discovery.rbac import collect_role_assignments


class RoleAssignmentTests(unittest.TestCase):
    def resource(self, rid):
        return {
            "id": rid, "name": rid.rsplit("/", 1)[-1],
            "subscription_id": "sub", "subscription_name": "Subscription",
            "tenant_id": "tenant", "resource_group": "rg",
            "type": "Microsoft.CognitiveServices/accounts",
        }

    def test_direct_inherited_conditions_and_cached_role_names(self):
        resource = self.resource("/subscriptions/sub/resourceGroups/rg/providers/"
                                 "Microsoft.CognitiveServices/accounts/ai")
        project = self.resource(resource["id"] + "/projects/project")
        definition_id = "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/reader"
        inherited = {
            "id": "/providers/Microsoft.Management/managementGroups/root/providers/"
                  "Microsoft.Authorization/roleAssignments/inherited",
            "properties": {
                "scope": "/providers/Microsoft.Management/managementGroups/root",
                "principalId": "group", "principalType": "Group",
                "roleDefinitionId": definition_id,
            },
        }
        direct = {
            "id": resource["id"] + "/providers/Microsoft.Authorization/roleAssignments/direct",
            "properties": {
                "scope": resource["id"].upper() + "/", "principalId": "user",
                "principalType": "User", "roleDefinitionId": definition_id.upper(),
                "condition": "test-condition", "conditionVersion": "2.0",
            },
        }

        class Client:
            def __init__(self):
                self.get_calls = []
                self.list_calls = []

            def list(self, path, version):
                self.list_calls.append(path)
                return [inherited, direct, inherited]

            def get(self, path, version):
                self.get_calls.append(path)
                return {"properties": {"roleName": "Reader", "type": "BuiltInRole"}}

        client = Client()
        rows = collect_role_assignments(client, [resource, project])
        self.assertEqual(len(rows), 4)
        self.assertEqual(len(client.get_calls), 1)
        self.assertEqual([r["assignment_relationship"] for r in rows],
                         ["inherited", "direct", "inherited", "inherited"])
        self.assertTrue(all(r["role_name"] == "Reader" for r in rows))
        self.assertEqual(rows[1]["condition"], "test-condition")
        self.assertEqual(rows[0]["principal_type"], "Group")
        self.assertEqual(rows[2]["foundry_resource_id"], project["id"])
        for path in client.list_calls:
            self.assertEqual(parse_qs(urlsplit(path).query)["$filter"], ["atScope()"])

    def test_failed_role_lookup_keeps_assignment_with_unresolved_role_name(self):
        resource = self.resource("/subscriptions/sub/resources/ai")

        class Client:
            def list(self, path, version):
                return [{"id": "assignment", "properties": {
                    "roleDefinitionId": "/roles/missing", "principalId": "principal",
                    "scope": resource["id"],
                }}]

            def get(self, path, version):
                return None

        row = collect_role_assignments(Client(), [resource])[0]
        self.assertEqual(row["principal_id"], "principal")
        self.assertEqual(row["role_definition_id"], "/roles/missing")
        self.assertEqual(row["role_name"], "")
        self.assertEqual(row["assignment_relationship"], "direct")

    def test_empty_resources_do_not_make_requests(self):
        self.assertEqual(collect_role_assignments(None, []), [])
