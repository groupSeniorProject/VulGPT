import os
import pandas as pd
import streamlit as st
import plotly.express as px
from dotenv import load_dotenv
from neo4j import GraphDatabase
# from langchain_community.graphs import Neo4jGraph
# import matplotlib.pyplot as plt

load_dotenv(override=True)

uri = os.getenv("URI")
username = os.getenv("USERNAME")
password = os.getenv("PASSWORD")

driver = GraphDatabase.driver(uri=uri, auth=(username, password))

@st.cache_data
def execute_query(query, column_name: str):
    with driver.session() as session:
        result = session.run(query)
        names = [record['name'] for record in result]
        df = pd.DataFrame(names, columns=[column_name])
        return df

@st.cache_data
def get_total_node_vulns(query, total_nodes: str):
    with driver.session() as session:
        result = session.run(query)
        return result.single()[total_nodes]

def search_results(df, text_search: str):
    m1 = df["Ecosystems"].str.contains(text_search)
    df_search = df[m1]
    return df_search

def run():
    st.title("VulGPT")

    if driver is not None:

        # returns total number of node vulns
        total_nodes = get_total_node_vulns("MATCH (n) RETURN COUNT(n) as total_nodes", 'total_nodes')
        st.write(f"Total Vulnerabilities: {total_nodes}")

        text_search = st.text_input("Search Vulnerabilities")

        query = execute_query("MATCH (n:Ecosystem) RETURN n.ecosystem_name AS name", 'Ecosystems')
        st.write(query)

        # MATCH (n:Ecosystem) WHERE n.ecosystem_name = "PyPI" RETURN COUNT(n) -> 1

        if text_search:
            st.write(search_results(query, text_search))

        

        # package_name = execute_query("MATCH (n:Vulnerability) RETURN n.package_name AS package_name")
        # df = pd.DataFrame(query)
        # df_pn = pd.DataFrame(package_name)
        # st.write(f"Total: {df['Vulnerability'].count()}")

        # package_name_count = df_pn['package_name'].value_counts()
        # fig_pie = px.pie(package_name_count,
        #                  values=package_name_count.values,
        #                  names=package_name_count.index,
        #                  title="Pie Chart")
        # st.plotly_chart(fig_pie)

    
if __name__ == "__main__":
    run()