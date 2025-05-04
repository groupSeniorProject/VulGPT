import asyncio
from time import time
from neo4j import AsyncGraphDatabase
from vul_auto_update.config.config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

class Neo4jManager:
    def __init__(self):
        self.driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    async def close(self):
        await self.driver.close()

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

    # updated functions below
        
    async def create_constraint(self):
        constraint_queries = [
            """
            CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability)
            REQUIRE v.id IS UNIQUE
            """,
            """
            CREATE CONSTRAINT IF NOT EXISTS FOR (e:Ecosystem)
            REQUIRE e.name IS UNIQUE
            """
        ]

        async with self.driver.session() as session:
            for q in constraint_queries:
                await session.run(q)

    async def upload_chunk(self, chunk):
        query = """
            UNWIND $vulnerabilities AS vuln

            MERGE (v:Vulnerability {id: vuln.id})
            SET v.summary = vuln.summary,
                v.details = vuln.details,
                v.published = vuln.published,
                v.date_modified = vuln.date_modified

            WITH v, vuln.affected AS affected_list
            UNWIND affected_list AS affected

            MERGE (e:Ecosystem {name: affected.package.ecosystem})
            MERGE (v)-[:IN_ECOSYSTEM]->(e)
            """

        async with self.driver.session(database='neo4j') as session:
            await session.execute_write(
                lambda tx: tx.run(query, vulnerabilities=chunk)
        )
    
    def chunkify(self, lst, chunk_size):
        for i in range(0, len(lst), chunk_size):
            yield lst[i:i + chunk_size]

    async def insert_all_vulnerabilities(self, vulnerabilities, chunk_size=1500, MAX_CONCURRENCY=5):
        chunks = self.chunkify(vulnerabilities, chunk_size)
        sem = asyncio.Semaphore(MAX_CONCURRENCY)

        async def limited_insert(idx, chunk):
            async with sem:
                start = time()
                await self.upload_chunk(chunk)
                elapsed = time() - start
                print(f"[Chunk {idx}] Inserted {len(chunk)} records in {elapsed:.2f}s")

        tasks = [asyncio.create_task(limited_insert(idx, chunk)) for idx, chunk in enumerate(chunks)]
        await asyncio.gather(*tasks)