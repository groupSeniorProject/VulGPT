import os
import pandas as pd
import streamlit as st
import plotly.express as px
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv(override=True)

uri = os.getenv("URI")
username = os.getenv("USERNAME")
password = os.getenv("PASSWORD")

driver = GraphDatabase.driver(uri=uri, auth=(username, password))

@st.cache_data
def execute_query(query, column_name: str):
    with driver.session() as session:
        result = session.run(query)
        if column_name:
            names = [record['name'] for record in result]
            return pd.DataFrame(names, columns=[column_name])
        else:
            return pd.DataFrame(result)


@st.cache_data
def get_total_node_vulns(query, total_nodes: str):
    with driver.session() as session:
        result = session.run(query)
        return result.single()[total_nodes]

@st.cache_data
def unique_eco_pie_chart(query):
    with driver.session() as session:
        result = session.run(query)
        records = result.data()
        eco_df = pd.DataFrame(records)
        eco_counts = eco_df['clean_name'].value_counts().reset_index()
        eco_counts.columns = ['Ecosystem', 'Count']

        # Pie chart
        fig = px.pie(
            eco_counts,
            names='Ecosystem',
            values='Count',
            title=f'Ecosystem Name Distribution',
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

@st.cache_data
def get_ecosystem_list():
    query = "MATCH (n:Ecosystem) RETURN split(n.ecosystem_name, ':')[0] AS name"
    df = execute_query(query, 'Ecosystems')
    return [""] + df['Ecosystems'].dropna().unique().tolist()

def search_results(df: pd.DataFrame, text_search: str):
    m1 = df["Ecosystems"].str.lower().str.contains(text_search.lower())
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
        tb2, tb3 = st.tabs([ "Ecosystems", "Github Repo"])

        with tb2:
            st.write(f"Total Vulnerabilities: {total_nodes}")


            ecosystem_list = get_ecosystem_list()
            selected_ecosystem = st.selectbox("Select Ecosystem", options=ecosystem_list)

            query = execute_query(f"MATCH (n:Ecosystem) RETURN n.ecosystem_name AS name", 'Ecosystems')

            unique_eco_pie_chart("MATCH (n:Ecosystem) RETURN split(n.ecosystem_name, ':')[0] AS clean_name")

            if selected_ecosystem:
                query = f""" MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(g:Ecosystem) 
                                WHERE g.ecosystem_name STARTS WITH '{selected_ecosystem}'
                                RETURN v.id as `Vulnerability ID`, g.ecosystem_name, v.details as Details, v.minimal_affected_versions as `Affected Versions`
                                limit 50
                """
                ecosystem_data = execute_query(query, column_name=None)

                if ecosystem_data.empty:
                    st.write(f"No vulnerabilities found in {selected_ecosystem}.")
                else:
                    for col in ecosystem_data.columns:
                            ecosystem_data[col] = ecosystem_data[col].apply(lambda x: str(x) if isinstance(x, list) else x)
                        
                    st.subheader(f"Vulnerabilities in {selected_ecosystem}")
                    specific_ecosystem = execute_query(f"""MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(g:Ecosystem) 
                                WHERE g.ecosystem_name STARTS WITH '{selected_ecosystem}'
                                RETURN  g.ecosystem_name AS `name` """, "Ecosystem Name")
                    specific_ecosystem = [""] + specific_ecosystem['Ecosystem Name'].dropna().unique().tolist()
                    selected_specific_ecoystem = st.selectbox("Select Specific Ecosystem", options=specific_ecosystem, index=0, key ="None")
                    
                    # Problem: takes long time, query will need to be indexed
                    if selected_specific_ecoystem:
                        query = f""" MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(g:Ecosystem) 
                                    WHERE g.ecosystem_name STARTS WITH '{selected_specific_ecoystem}'
                                    RETURN v.id as `Vulnerability ID`, v.details as Details, v.minimal_affected_versions as `Affected Versions`
                                    limit 50
                        """
                        ecosystem_data = execute_query(query, column_name=None)
                        if ecosystem_data.empty:
                            st.write(f"No vulnerabilities found in {selected_specific_ecoystem}.")
                        else:
                            for col in ecosystem_data.columns:
                                ecosystem_data[col] = ecosystem_data[col].apply(lambda x: str(x) if isinstance(x, list) else x)
                            st.subheader(f"Vulnerabilities in {selected_specific_ecoystem}")

                    st.write(ecosystem_data)

        with tb3: 

            total_github = get_total_node_vulns(f"""MATCH (v:Vulnerability)-[:IN_GITHUB]->(g:GitHub)
                                                WHERE v.minimal_affected_versions is NOT NULL and v.minimal_affected_versions <> "No solution"
                                                RETURN count(v.id) as total_nodes """, "total_nodes")
            st.write(f"Total: {total_github}")

            query1 = execute_query(f"""MATCH (v:Vulnerability)-[:IN_GITHUB]->(g:GitHub)
                                    WHERE v.minimal_affected_versions is NOT NULL and v.minimal_affected_versions <> "No solution"
                                    RETURN v.id as ID, g.name, v.minimal_affected_versions, g.lang_breakdown
                                    limit 50 """, column_name=None)
            st.write(query1)


            # previous_next_page_buttons()




    
if __name__ == "__main__":
    run()