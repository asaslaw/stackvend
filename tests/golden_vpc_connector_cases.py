"""FD-4BH (golden VPC connector): typed intents and contexts with the sha256 of their gate-clean render
(custom.tf.json + intent_facts.tf.json) as computed by the code before FD-4BH (workload-sub-no-expiry 87be7e2e).
tests/test_golden_vpc_connector.py checks today's code gives exactly these for every context WITHOUT the platform
connector (render byte-identity), and that the connector context differs only by the connector's new form.
Data only: no import of the code under test."""


def doc(modules=(), resources=(), outputs=()):
    return {"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources),
            "outputs": list(outputs)}


BUCKET = {"module": "storage-bucket", "name": "uploads", "args": {"bucket_name_suffix": "uploads"}}
SQL = {"module": "database-cloudsql", "name": "db", "realizes": "db", "args": {}}
REDIS = {"module": "cache-redis", "name": "cache", "realizes": "cache", "args": {}}
SHOP = {"shop": ("module.compute", "compute-cloudrun")}
SQL_READ = {"services": SHOP, "topology_resources": {"db": "google_sql_database_instance"},
            "service_reads": (("shop", "db"),)}
BOTH_READ = {"services": SHOP, "topology_resources": {"db": "google_sql_database_instance",
                                                      "cache": "google_redis_instance"},
             "service_reads": (("shop", "cache"), ("shop", "db"))}

# (name, intent document, context args, network facts in the context)
NO_CONNECTOR_CASES = [
    ("bucket_no_network", doc([BUCKET]), {}, False),
    ("sql_network_no_connector", doc([SQL]), SQL_READ, True),
    ("sql_network_psa_no_connector", doc([SQL]), dict(SQL_READ, psa_range=True), True),
    ("sql_and_redis_network_no_connector", doc([SQL, REDIS]), BOTH_READ, True),
    ("bucket_with_network_facts", doc([BUCKET]), {}, True),
]
CONNECTOR_CASES = [
    ("sql_connector", doc([SQL]), dict(SQL_READ, vpc_connector=True), True),
    ("sql_and_redis_connector_psa", doc([SQL, REDIS]), dict(BOTH_READ, vpc_connector=True, psa_range=True), True),
]

# computed with the code of 87be7e2e (before FD-4BH): sha256 of json.dumps(render.files, sort_keys=True)
PRE_CHANGE = {
    "bucket_no_network": "6bd77182c3e38fdd132ff7d358743a8c1a4c9efdc56431798f2108c57bee86cd",
    "sql_network_no_connector": "29b2dae11a72b2dd81905df9f0d588901c1092a0f015089a62ebbe286bf831e2",
    "sql_network_psa_no_connector": "c35bd643eabf145e66c1a55a668c86a2483f5755ff7604170222ba286af755c7",
    "sql_and_redis_network_no_connector": "f4c3c1840900f0b7f4ee69d1636d9773b25d51878ffdc71e30e86184f7eb1839",
    "bucket_with_network_facts": "6bd77182c3e38fdd132ff7d358743a8c1a4c9efdc56431798f2108c57bee86cd",
    "sql_connector": "7bbd92e06650827f5826e8429d8ad29252f2f46c57855b579c80dd94c8d2d1ae",
    "sql_and_redis_connector_psa": "6dc3912335191d860e4d820f719804737aec6189807192b02aaf39248bbdf45a",
}

# The TI-5c raw connector the code before FD-4BH rendered into intent_facts.tf.json (exact body)
LEGACY_CONNECTOR_BODY = {
    "name": "stackvend-conn",
    "project": "${var.project_id}",
    "region": "${var.region}",
    "network": "${module.stackvend_network.network_name}",
    "ip_cidr_range": "${var.connector_cidr}",
    "min_instances": 2,
    "max_instances": 3,
    "depends_on": ["module.foundation", "module.stackvend_network"],
}


def ctx_of(ii, args, network):
    """The IntentContext of a case (`ii` is the shared.iac_intent module under test)."""
    facts = dict(ii.default_facts())
    facts.update(ii.platform_zone_facts())
    if network:
        facts.update(ii.platform_network_facts())
    return ii.IntentContext(facts=facts, **args)
