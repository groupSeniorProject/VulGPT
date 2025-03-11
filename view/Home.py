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

def execute_query(query):
    with driver.session() as session:
        result = session.run(query)
        records = result.data()
        return pd.DataFrame(records)

def run():
    st.title("VulGPT")

    if driver is not None:
        query = execute_query("MATCH (n:Vulnerability) RETURN n.package_name AS package_name")
        df = pd.DataFrame(query)

        package_name_count = df['package_name'].value_counts()
        fig_pie = px.pie(package_name_count,
                         values=package_name_count.values,
                         names=package_name_count.index,
                         title="Pie Chart")
        st.plotly_chart(fig_pie)

    
if __name__ == "__main__":
    run()