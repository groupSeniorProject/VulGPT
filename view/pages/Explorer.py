import streamlit as st
from streamlit_manager import Neo4jManager

def run():
    driver = Neo4jManager()

    vulnerability_explorer, github_repo_explorer = st.tabs(['Vulnerability Explorer', 'GitHub Repo'])

    PAGE_SIZE = 10

    with vulnerability_explorer:

        ecosystem_list = driver.get_ecosystem_list()
        selected_ecosystem = st.sidebar.selectbox("Select Ecosystem", options=ecosystem_list, key="selected_ecosystem")

        if "page_number" not in st.session_state:
            st.session_state.page_number = 0

        if "previous_ecosystem" not in st.session_state:
            st.session_state.previous_ecosystem = selected_ecosystem

        # Check if ecosystem changed
        if selected_ecosystem != st.session_state.previous_ecosystem:
            st.session_state.page_number = 0
            st.session_state.previous_ecosystem = selected_ecosystem  # Update to new value

        skip_count = st.session_state.page_number * PAGE_SIZE

        if selected_ecosystem == "":
            vulnerabilities_df = driver.get_vulnerabilities(skip=skip_count, limit=PAGE_SIZE)
        else:
            vulnerabilities_df = driver.get_vulnerabilities_by_ecosystem(selected_ecosystem, skip=skip_count, limit=PAGE_SIZE)


        with st.spinner("Fetching vulnerabilities..."):
            if vulnerabilities_df.empty:
                st.warning("No vulnerabilities found.")
            else:
                for _, row in vulnerabilities_df.iterrows():
                    with st.container():
                        published = driver.parse_date(str(row['published']))
                        st.markdown(f"""
                        <div style="border:1px solid #ccc; padding:10px; border-radius:8px; margin-bottom:10px;">
                            <h5>Ecosystem: <span style="color: #007BFF;">{row['ecosystem_name']}</span> | ID: {row['id']} |
                            Published: {published}</h5>
                            <p>Summary: {row['summary']}</p>
                        </div>
                        """, unsafe_allow_html=True)
        
        # ------------------ Navigation ------------------
        col1, col2, col3 = st.columns([1, 1, 1])
        with col1:
            st.button("Prev", on_click=lambda: st.session_state.update(
                {"page_number": st.session_state.page_number - 1}),
                disabled=st.session_state.page_number == 0
            )

        with col2:
            st.markdown(
                f"<div font-size: 18px;'>Page <b>{st.session_state.page_number + 1}</b></div>",
                unsafe_allow_html=True
            )

        with col3:
            st.button("Next", on_click=lambda: st.session_state.update(
                {"page_number": st.session_state.page_number + 1})
            )
    
    with github_repo_explorer:
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

if __name__ == "__main__":
    run()