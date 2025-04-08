from neo4j import GraphDatabase
from vul_auto_update.config.config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

class Neo4jManager:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    def close(self):
        self.driver.close()

    # add/update cwe
    def upsert_cwe(self, cwe_id, name, description):
        with self.driver.session() as session:
            session.execute_write(self._upsert_cwe, cwe_id, name, description)

    @staticmethod
    def _upsert_cwe(tx, cwe_id, name, description):
        query = (
            "MERGE (c:CWE {id: $cwe_id}) "
            "SET c.name = $name, c.description = $description "
            "RETURN c"
        )
        result = tx.run(query, cwe_id=cwe_id, name=name, description=description)
        node = result.single()
        if node:
            print(f"Upserted CWE: {node['c']}")


    def upsert_osv(self, osv_id, summary, affected_versions):
        with self.driver.session() as session:
            session.execute_write(self._upsert_osv, osv_id, summary, affected_versions)

    @staticmethod
    def _upsert_osv(tx, osv_id, summary, affected_versions):
        query = (
            "MERGE (o:OSV {id: $osv_id}) "
            "SET o.summary = $summary "
            "WITH o "
            "UNWIND $affected_versions AS version "
            "MERGE (v:Version {name: version}) "
            "MERGE (o)-[:AFFECTS_VERSION]->(v) "
            "RETURN o"
        )

        result = tx.run(query, osv_id=osv_id, summary=summary, affected_versions=affected_versions)
        node = result.single()
        if node:
            print(f"Upserted OSV: {node['o']}")


    def view_cwe(self):
        with self.driver.session() as session:
            result = session.read_transaction(self._get_all_cwe)
            for record in result:
                print(record)

    @staticmethod
    def _get_all_cwe(tx):
        query = (
            "MATCH (c:CWE) "
            "RETURN c.id AS id, c.name AS name, c.description AS description"
        )
        return list(tx.run(query))

    # view all osv
    def view_osv(self):
        with self.driver.session() as session:
            result = session.read_transaction(self._get_all_osv)
            for record in result:
                print(record)

    @staticmethod
    def _get_all_osv(tx):
        query = (
            "MATCH (o:OSV)-[:AFFECTS]->(p:Package) "
            "RETURN o.id AS id, o.summary AS summary, o.severity AS severity, collect(p.name) AS affected_packages"
        )
        return list(tx.run(query))


    def delete_cwe(self, cwe_id):
        with self.driver.session() as session:
            session.execute_write(self._delete_cwe, cwe_id)

    @staticmethod
    def _delete_cwe(tx, cwe_id):
        query = (
            "MATCH (c:CWE {id: $cwe_id}) "
            "DETACH DELETE c"
        )
        tx.run(query, cwe_id=cwe_id)
        print(f"Deleted CWE with ID: {cwe_id}")


    def delete_osv(self, osv_id):
        with self.driver.session() as session:
            session.execute_write(self._delete_osv, osv_id)

    @staticmethod
    def _delete_osv(tx, osv_id):
        query = (
            "MATCH (o:OSV {id: $osv_id}) "
            "DETACH DELETE o"
        )
        tx.run(query, osv_id=osv_id)
        print(f"Deleted OSV with ID: {osv_id}")
        