import pandas as pd
import streamlit as st
import plotly.express as px
from streamlit_manager import Neo4jManager

def run():
    driver = Neo4jManager()
    st.set_page_config(layout="wide")

    st.title("VulGPT")

    if driver is not None:

        # returns total number of node vulns
        total_nodes = driver.get_total_node_vulns("MATCH (n) RETURN COUNT(n) as total_nodes", 'total_nodes')
        tb2, tb3, tb4 = st.tabs(["Ecosystems", "Github Repo", "Testing"])

        with tb2:
            st.write(f"Total Vulnerabilities: {total_nodes}")

            ecosystem_list = driver.get_ecosystem_list()
            selected_ecosystem = st.selectbox("Select Ecosystem", options=ecosystem_list)


            driver.unique_eco_pie_chart()

            if selected_ecosystem:
                query = f"""
                MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(g:Ecosystem) 
                WHERE g.ecosystem_name STARTS WITH '{selected_ecosystem}'
                RETURN v.id as `Vulnerability ID`, g.ecosystem_name, v.details as Details, v.minimal_affected_versions as `Affected Versions`
                limit 50
                """
                ecosystem_data = driver.execute_query(query, column_name=None)

                if ecosystem_data.empty:
                    st.write(f"No vulnerabilities found in {selected_ecosystem}.")
                else:
                    for col in ecosystem_data.columns:
                        ecosystem_data[col] = ecosystem_data[col].apply(lambda x: str(x) if isinstance(x, list) else x)
                        
                    st.subheader(f"Vulnerabilities in {selected_ecosystem}")

                    specific_ecosystem = driver.execute_query(f"""
                    MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(g:Ecosystem) 
                    WHERE g.ecosystem_name STARTS WITH '{selected_ecosystem}'
                    RETURN  g.ecosystem_name AS `name` """, "Ecosystem Name")

                    specific_ecosystem = [""] + specific_ecosystem['Ecosystem Name'].dropna().unique().tolist()
                    selected_specific_ecoystem = st.selectbox("Select Specific Ecosystem", options=specific_ecosystem, index=0, key ="None")
                    
                    # Problem: takes long time, query will need to be indexed
                    if selected_specific_ecoystem:
                        query = f"""
                        MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(g:Ecosystem) 
                        WHERE g.ecosystem_name STARTS WITH '{selected_specific_ecoystem}'
                        RETURN v.id as `Vulnerability ID`, v.details as Details, v.minimal_affected_versions as `Affected Versions`
                        limit 50
                        """

                        ecosystem_data = driver.execute_query(query, column_name=None)
                        if ecosystem_data.empty:
                            st.write(f"No vulnerabilities found in {selected_specific_ecoystem}.")
                        else:
                            for col in ecosystem_data.columns:
                                ecosystem_data[col] = ecosystem_data[col].apply(lambda x: str(x) if isinstance(x, list) else x)
                            st.subheader(f"Vulnerabilities in {selected_specific_ecoystem}")

                    st.write(ecosystem_data)

        with tb3: 
            total_github = driver.get_total_node_vulns(f"""
            MATCH (v:Vulnerability)-[:IN_GITHUB]->(g:GitHub)
            WHERE v.minimal_affected_versions is NOT NULL and v.minimal_affected_versions <> "No solution"
            RETURN count(v.id) as total_nodes
            """,
            "total_nodes")

            st.write(f"Total: {total_github}")

            query1 = driver.execute_query(f"""
            MATCH (v:Vulnerability)-[:IN_GITHUB]->(g:GitHub)
            WHERE v.minimal_affected_versions is NOT NULL and v.minimal_affected_versions <> "No solution"
            RETURN v.id as ID, g.name, v.minimal_affected_versions, g.lang_breakdown
            limit 50
            """,
            column_name=None)
            st.write(query1)

            # previous_next_page_buttons()

        with tb4:
            PAGE_SIZE = 20

            if "page_number" not in st.session_state:
                st.session_state.page_number = 0

            st.title("Vulnerability Explorer")

            ecosystem_list = driver.get_ecosystem_list()
            selected_ecosystem = st.sidebar.selectbox("Select Ecosystem", options=ecosystem_list, key="selected_ecosystem", on_change=driver.reset_pagination())
            
            skip_count = st.session_state.page_number * PAGE_SIZE
            with st.spinner("Fetching vulnerabilities..."):
                    if selected_ecosystem == "":
                        vulnerabilities_df = driver.get_vulnerabilities(skip=skip_count, limit=PAGE_SIZE)
                    else:
                        st.subheader(f"Vulnerabilities in {selected_ecosystem}")
                        vulnerabilities_df = driver.get_vulnerabilities_by_ecosystem(selected_ecosystem, skip=skip_count, limit=PAGE_SIZE)
                        
                        specific_ecosystem = driver.execute_query(f"""
                            MATCH (v:Vulnerability)-[:IN_ECOSYSTEM]->(g:Ecosystem) 
                            WHERE g.ecosystem_name STARTS WITH '{selected_ecosystem}'
                            RETURN  g.ecosystem_name AS `name` """, "Ecosystem Name"               
                        )
                        specific_ecosystem = [""] + specific_ecosystem['Ecosystem Name'].dropna().unique().tolist()

                        selected_specific_ecoystem = st.sidebar.selectbox("Select Specific Ecosystem", options=specific_ecosystem, index=0, key="specific_ecosystem")

                        if selected_specific_ecoystem:
                            st.subheader(f"Vulnerabilities in {selected_specific_ecoystem}")
                            vulnerabilities_df = driver.get_vulnerabilities_by_ecosystem(selected_specific_ecoystem, skip=skip_count, limit=PAGE_SIZE)

                            


                    if vulnerabilities_df.empty:
                        st.warning("No vulnerabilities found.")

                    else:
                        for _, row in vulnerabilities_df.iterrows():
                            with st.container():
                                st.markdown(f"""
                                <div style="border:1px solid #ccc; padding:10px; border-radius:8px; margin-bottom:10px;">
                                    <h5>ID: {row['id']} | Ecosystem: <span style="color: #007BFF;">{row['ecosystem_name']}</span></h5>
                                    <p>{row['summary']}</p>
                                </div>
                                """, unsafe_allow_html=True)

            # ------------------ Navigation ------------------
            col1, col2, _ = st.columns([1, 1, 3])
            with col1:
                if st.button("Previous"):
                    driver.prev_page()
            with col2:
                if st.button("Next"):
                    driver.next_page()

if __name__ == "__main__":
    run()