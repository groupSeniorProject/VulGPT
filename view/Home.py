import os
import pandas as pd
import streamlit as st
import plotly.express as px
from dotenv import load_dotenv
from neo4j import GraphDatabase
# from langchain_community.graphs import Neo4jGraph
# import matplotlib.pyplot as plt

load_dotenv(override=True)

uri = st.secrets.db_credentials.uri
username = st.secrets.db_credentials.username
password = st.secrets.db_credentials.password

driver = GraphDatabase.driver(uri=uri, auth=(username, password))

def execute_query(query):
    with driver.session() as session:
        result = session.run(query)
        records = result.data()
        return pd.DataFrame(records)

def run():
    st.title("VulGPT")

    st.write("Description of project here")

    if driver is not None:
        tb1,tb2,tb3 = st.tabs(["Database", "Piechart","Search"])

        with tb1:
            dataquery =  """MATCH (v:Vulnerability)
                            RETURN v.id as ID, v.details as details
                            """
            dbquery = execute_query(dataquery)
            st.write(dbquery)

        with tb2: 
            query = execute_query("MATCH (n:Vulnerability) RETURN n.package_name AS package_name")
            df = pd.DataFrame(query)

            package_name_count = df['package_name'].value_counts()
            fig_pie = px.pie(package_name_count,
                            values=package_name_count.values,
                            names=package_name_count.index,
                            title="Pie Chart")
            st.plotly_chart(fig_pie)

        with tb3:
            with st.form(key = "searchForm"):
                package_list = query["package_name"].dropna().unique().tolist() #Utilized chatgpt to figure out how to return a list
                selectedPackage = st.selectbox("Package name", package_list, index=None, placeholder="Select package name")
                searchdb = st.form_submit_button("Search")
                if searchdb:
                    searchQuery = f"""
                                MATCH (v:Vulnerability)
                                WHERE v.package_name = "{selectedPackage}"
                                RETURN v.id as ID,v.package_name as package_name, v.details as details
                                """
                    st.write(execute_query(searchQuery))



    
if __name__ == "__main__":
    run()