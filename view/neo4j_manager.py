import asyncio
import pandas as pd
from time import time
import streamlit as st
from neo4j import AsyncGraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

class Neo4jManager:
    def __init__(self):
        self.driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self.database_name = "neo4j"

    async def close(self):
        await self.driver.close()
        
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
                v.modified = vuln.modified

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