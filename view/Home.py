import os
import pandas as pd
import streamlit as st
import plotly.express as px
from dotenv import load_dotenv
from neo4j import GraphDatabase

# Load environment variables
load_dotenv(override=True)
uri = os.getenv("URI")
username = os.getenv("USER")
password = os.getenv("PASSWORD")

# Connect to Neo4j
driver = GraphDatabase.driver(uri=uri, auth=(username, password))

# Query executor
def execute_query(query):
    with driver.session() as session:
        result = session.run(query)
        records = result.data()
        return pd.DataFrame(records)

# Streamlit app
def run():
    st.title("VulGPT")

    if driver is not None:
        # Vulnerabilities Table
        vuln_query = execute_query("""
            MATCH (n:Vulnerability) RETURN n AS Vulnerability LIMIT 25
        """)
        st.subheader("Sample Vulnerabilities")
        st.dataframe(vuln_query)
        st.write(f"Total: {vuln_query['Vulnerability'].count()}")

        # Pie Chart of Ecosystems by Vulnerability Count
        st.subheader("Ecosystem Distribution by Vulnerability")

        # Query ecosystems with grouped vulnerability counts
        limit = 25
        eco_query = execute_query(f"""
            MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(e:Ecosystem)
            RETURN split(e.ecosystem_name, ":")[0] AS Ecosystem, count(v) AS VulnerabilityCount
            ORDER BY VulnerabilityCount DESC
            LIMIT {limit}
        """)

        if not eco_query.empty:
            # Create chart labels
            eco_query['Label'] = eco_query.apply(
                lambda row: f"{row['Ecosystem']} ({row['VulnerabilityCount']})", axis=1
            )

            # Plot pie chart
            fig = px.pie(
                eco_query,
                names='Label',
                values='VulnerabilityCount',
                title=f'Top {limit} Ecosystems by Vulnerability Count',
                color_discrete_sequence=px.colors.sequential.RdBu,
                hover_data=['VulnerabilityCount']
            )

            fig.update_traces(
                textinfo='none',
                pull=[0.03] * len(eco_query),
                marker=dict(line=dict(color='#000000', width=1)),
                hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percent: %{percent}<extra></extra>'
            )

            fig.update_layout(
                showlegend=True,
                legend_title_text='Ecosystem',
                height=750,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)"
            )

            st.plotly_chart(fig, use_container_width=True)

if __name__ == "__main__":
    run()
