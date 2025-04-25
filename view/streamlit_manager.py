import pandas as pd
import streamlit as st
import plotly.express as px
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
                    df,
                    names='Label',  # show ecosystem and count in legend
                    values='Count',
                    title='Vulnerabilities per Ecosystem',
                    color_discrete_sequence=px.colors.sequential.RdBu,
                    hover_data=['Count']
                )

                fig.update_traces(
                    textinfo='none',
                    pull=[0.03] * len(df),
                    marker=dict(line=dict(color='#000000', width=1)),
                    hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percent: %{percent}<extra></extra>'
                )

                fig.update_layout(
                    showlegend=True,
                    legend_title_text='Ecosystem',
                    margin=dict(t=40, b=20, l=20, r=20),
                    height=750,
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)"
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
        MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(e:Ecosystem {ecosystem_name: $ecosystem})
        RETURN v.id AS id, v.summary AS summary, e.ecosystem_name AS ecosystem_name
        SKIP $skip LIMIT $limit
        """
        with _self.driver.session() as session:
            result = session.run(query, ecosystem=ecosystem, skip=skip, limit=limit)
            return pd.DataFrame([record.data() for record in result])
        
    def get_vulnerabilities(self, skip, limit):
        query = """
        MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(e:Ecosystem)
        RETURN v.id AS id, v.summary AS summary, e.ecosystem_name AS ecosystem_name
        SKIP $skip LIMIT $limit
        """
        with self.driver.session() as session:
            result = session.run(query, skip=skip, limit=limit)
            return pd.DataFrame([r.data() for r in result]) 

    # def search_results(df: pd.DataFrame, text_search: str):
    #     m1 = df["Ecosystems"].str.lower().str.contains(text_search.lower())
    #     df_search = df[m1]
    #     return df_search

    # def previous_next_page_buttons(self):
    #     col1, col2 = st.columns([1, 1])
    #     with col1:
    #         st.button('Previous Page')
    #     with col2:
    #         st.button('Next Page')