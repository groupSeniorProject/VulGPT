import os
import pandas as pd
import streamlit as st
import plotly.express as px
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv(override=True)

URI = os.getenv("URI")
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")

driver = GraphDatabase.driver(uri=URI, auth=(USERNAME, PASSWORD))

@st.cache_data
def execute_query(query, node_name: str, column_name: str):
    with driver.session() as session:
        result = session.run(query)
        names = [record[node_name] for record in result]
        df = pd.DataFrame(names, columns=[column_name])
        return df
    
def execute_query1(query):
    with driver.session() as session:
        result = session.run(query)
        records = result.data()
        return pd.DataFrame(records)

@st.cache_data
def get_total_node_vulns(query, total_nodes: str):
    with driver.session() as session:
        result = session.run(query)
        return result.single()[total_nodes]

@st.cache_data
def unique_eco_pie_chart(query, clean_name: str):
    with driver.session() as session:
        result = session.run(query)
        records = result.data()
        eco_df = pd.DataFrame(records)
        eco_counts = eco_df[clean_name].value_counts().reset_index()
        eco_counts.columns = ['Ecosystem', 'Count']

        # Pie chart
        fig = px.pie(
            eco_counts,
            names='Ecosystem',
            values='Count',
            title='Ecosystem Name Distribution',
            color_discrete_sequence=px.colors.sequential.RdBu,
            hover_data=['Count']
        )

        fig.update_traces(
            textinfo='none',
            textposition='outside',
            pull=[0.03] * len(eco_counts),
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


def search_results(df: pd.DataFrame, text_search: str):
    m1 = df[text_search].str.lower().str.contains(text_search.lower())
    df_search = df[m1]
    return df_search

def previous_next_page_buttons():
    col1, col2 = st.columns([1, 1])
    with col1:
        st.button('Previous Page')
    with col2:
        st.button('Next Page')

def run():
    st.title("VulGPT")

    if driver is not None:

        # returns total number of node vulns
        total_nodes = get_total_node_vulns("MATCH (n) RETURN COUNT(n) as total_nodes", 'total_nodes')
        tb2, tb3 = st.tabs([ "Metrics", "Github Repo"])

        with tb2:
            st.write(f"Total Vulnerabilities: {total_nodes}")

            text_search = st.text_input("Search Vulnerabilities")

            query = execute_query(f"MATCH (n:Ecosystem) RETURN n.ecosystem_name AS name", "name", 'Ecosystems')

            unique_eco_pie_chart("MATCH (n:Ecosystem) RETURN split(n.ecosystem_name, ':')[0] AS clean_name", "clean_name")

            if text_search:
                st.write(search_results(query, text_search))

        with tb3: 
            total_github = get_total_node_vulns(f"""
            MATCH (v:Vulnerability)-[:IN_GITHUB]->(g:GitHub)
            WHERE v.minimal_affected_versions is NOT NULL and v.minimal_affected_versions <> "No solution"
            RETURN count(v.id) as total_nodes """, "total_nodes")

            st.write(f"Total: {total_github}")

            query1 = execute_query1(f"""
            MATCH (v:Vulnerability)-[:IN_GITHUB]->(g:GitHub)
            WHERE v.minimal_affected_versions is NOT NULL and v.minimal_affected_versions <> "No solution"
            RETURN v.id as ID, 
            g.name,
            v.minimal_affected_versions,
            g.lang_breakdown
            LIMIT 50""")

            st.write(query1)


            # previous_next_page_buttons()

if __name__ == "__main__":
    run()