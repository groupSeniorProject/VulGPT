import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime
from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

class Neo4jManager:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self.database_name = "neo4j"
        

    # note change self -> _self with using @st.cache_data

    @st.cache_data
    def execute_query(_self, query, column_name: str):
        with _self.driver.session(database=_self.database_name) as session:
            result = session.run(query)
            if column_name:
                names = [record['name'] for record in result]
                return pd.DataFrame(names, columns=[column_name])
            else:
                return pd.DataFrame(result)
            
    @st.cache_data
    def get_total_node_vulns(_self, query, total_nodes: str):
        with _self.driver.session() as session:
            result = session.run(query)
            return result.single()[total_nodes]
        
    @st.cache_data
    def get_ecosystem_list(_self):
        query = "MATCH (n:Ecosystem) RETURN split(n.ecosystem_name, ':')[0] AS name"
        df = _self.execute_query(query, 'Ecosystems')
        return [""] + df['Ecosystems'].dropna().unique().tolist()
    
    @st.cache_data
    def get_specific_ecosystem_list(_self, name: str):
        query = f"MATCH (n:Ecosystem) WHERE n.ecosystem_name STARTS WITH '{name}' RETURN n.ecosystem_name AS name"
        df = _self.execute_query(query, 'Ecosystems')
        return [""] + df['Ecosystems'].dropna().unique().tolist()
    
    @st.cache_data
    def get_github_list(_self):
        query = "MATCH (n:GitHub) RETURN n.name AS name"
        df = _self.execute_query(query, 'GitHub')
        return [""] + df['GitHub'].dropna().unique().tolist()
        
    @st.cache_data
    def unique_eco_pie_chart(_self):
        query = "MATCH (n:Ecosystem) RETURN DISTINCT split(n.ecosystem_name, ':')[0] AS name"

        df = pd.DataFrame(columns=["ecosystem", "count"])

        with _self.driver.session() as session:
            result = session.run(query)
            records = result.data()
            eco_df = pd.DataFrame(records)
            eco_list = eco_df['name'].tolist()
            
            for eco in eco_list:
                query_temp = f"""
                MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(e:Ecosystem)
                WHERE e.ecosystem_name STARTS WITH '{eco}'
                RETURN COUNT(split(e.ecosystem_name, ":")[0]) AS count
                """
                result = session.run(query_temp)
                records = result.data()
            
                if records:
                    count = records[0]['count']
                    df = pd.concat([df, pd.DataFrame([{"ecosystem": eco, "count": count}])], ignore_index=True)

            # Count vulnerabilities per ecosystem
            df.columns = ['Ecosystem', 'Count']
            if not df.empty:
                df['Label'] = df.apply(
                    lambda row: f"{row['Ecosystem']} ({row['Count']})", axis=1
                )

                # Plot pie chart
                fig = px.pie(
                    data_frame=df,
                    title=None,
                    names='Label',
                    values='Count',
                    hover_name='Ecosystem',
                    hover_data='Count',
                    height=600,
                )

                fig.update_traces(
                    # textinfo='none'
                )

                fig.update_layout(
                    showlegend=True,
                    legend_title_text='Ecosystems',
                    height=600,
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("No data to display.")

    @st.cache_data
    def unique_eco_bar_chart(_self):
        query = "MATCH (n:Ecosystem) RETURN DISTINCT split(n.ecosystem_name, ':')[0] AS name"

        df = pd.DataFrame(columns=["ecosystem", "count"])

        with _self.driver.session() as session:
            result = session.run(query)
            records = result.data()
            eco_df = pd.DataFrame(records)
            eco_list = eco_df['name'].tolist()
            
            for eco in eco_list:
                query_temp = f"""
                MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(e:Ecosystem)
                WHERE e.ecosystem_name STARTS WITH '{eco}'
                RETURN COUNT(split(e.ecosystem_name, ":")[0]) AS count
                """
                result = session.run(query_temp)
                records = result.data()
            
                if records:
                    count = records[0]['count']
                    df = pd.concat([df, pd.DataFrame([{"ecosystem": eco, "count": count}])], ignore_index=True)

            # Count vulnerabilities per ecosystem
            df.columns = ['Ecosystems', 'Count']
            if not df.empty:
                df['Label'] = df.apply(
                    lambda row: f"{row['Ecosystems']} ({row['Count']})", axis=1
                )

                # Plot bar chart
                fig = px.bar(
                    data_frame=df,
                    x='Ecosystems',
                    y='Count',
                    color='Ecosystems',
                    height=600,
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("No data to display.")

    def reset_pagination(self):
        st.session_state.page_number = 0

    def next_page(self):
        st.session_state.page_number += 1
    
    def prev_page(self):
        if st.session_state.page_number > 0:
            st.session_state.page_number -= 1

    def get_all_ecosystems(_self):
        query = "MATCH (n:Ecosystem) RETURN DISTINCT split(n.ecosystem_name, ':')[0] AS name"
        with _self.driver.session() as session:
            result = session.run(query)
            return [record["name"] for record in result]
        
    def get_vulnerabilities_by_ecosystem(_self, ecosystem: str, skip: int, limit: int) -> pd.DataFrame:
        query = """
        MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(e:Ecosystem)
        WHERE e.ecosystem_name STARTS WITH $ecosystem
        RETURN v.id AS id,
        v.summary AS summary,
        v.date_modified AS date_modified,
        v.published AS published,
        e.ecosystem_name AS ecosystem_name
        SKIP $skip LIMIT $limit
        """
        with _self.driver.session() as session:
            result = session.run(query, ecosystem=ecosystem, skip=skip, limit=limit)
            return pd.DataFrame([record.data() for record in result])
    
    def get_vulnerabilities(_self, skip, limit):
        query = """
        MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(e:Ecosystem)
        RETURN v.id AS id,
        v.summary AS summary,
        v.date_modified AS date_modified,
        v.published AS published,
        e.ecosystem_name AS ecosystem_name
        SKIP $skip LIMIT $limit
        """
        with _self.driver.session() as session:
            result = session.run(query, skip=skip, limit=limit)
            return pd.DataFrame([r.data() for r in result])
    
        
    def get_vulnerabilities_by_github(_self, skip: int, limit: int) -> pd.DataFrame:
        query = """
        MATCH (v:Vulnerability)-[:IN_GITHUB]->(g:GitHub)
        WHERE v.minimal_affected_versions is NOT NULL and v.minimal_affected_versions <> "No solution"
        RETURN v.id as ID, g.name as `name`,v.summary as summary, v.minimal_affected_versions as minimal, g.lang_breakdown as breakdown
        SKIP $skip LIMIT $limit
        """
        with _self.driver.session() as session:
            result = session.run(query, skip=skip, limit=limit)
            return pd.DataFrame([record.data() for record in result])
    
    def get_specific_vulnerabilities_by_github(_self, github: str, skip: int, limit: int) -> pd.DataFrame:
        query = """
        MATCH (v:Vulnerability)-[:IN_GITHUB]->(g:GitHub)
        WHERE g.name = $github and v.minimal_affected_versions is NOT NULL and v.minimal_affected_versions <> "No solution"
        RETURN v.id as ID, g.name as `name`,v.summary as summary, v.minimal_affected_versions as minimal, g.lang_breakdown as breakdown
        SKIP $skip LIMIT $limit
        """
        with _self.driver.session() as session:
            result = session.run(query, github=github, skip=skip, limit=limit)
            return pd.DataFrame([record.data() for record in result])
        
    def parse_date(self, date_str):
        # Try parsing with microseconds first
        try:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ").date()
        except ValueError:
            # If it fails, try parsing without microseconds
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ").date()