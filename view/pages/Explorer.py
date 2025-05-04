import json
import streamlit as st
from streamlit_manager import Neo4jManager

def run():
    driver = Neo4jManager()

    vulnerability_explorer, github_repo_explorer = st.tabs(['Vulnerability Explorer', 'GitHub Repo'])

    PAGE_SIZE = 10

    with vulnerability_explorer:
        ecosystem_list = driver.get_ecosystem_list()
        selected_ecosystem = st.selectbox("Select Ecosystem", options=ecosystem_list, key="selected_ecosystem")

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
            specific_ecosystem = driver.get_specific_ecosystem_list(selected_ecosystem)
            selected_specific_ecosystem = st.selectbox("Specific Ecosystem", options=specific_ecosystem, key="specific_ecosystem")
            if "previous_specific_ecosystem" not in st.session_state:
                st.session_state.previous_specific_ecosystem = selected_specific_ecosystem

            if selected_specific_ecosystem != st.session_state.previous_specific_ecosystem:
                st.session_state.page_number = 0
                st.session_state.previous_specific_ecosystem = selected_specific_ecosystem  

            if selected_specific_ecosystem != "":
                vulnerabilities_df = driver.get_vulnerabilities_by_ecosystem(selected_specific_ecosystem, skip=skip_count, limit=PAGE_SIZE)

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
        with st.container():
            col1, col2, col3 = st.columns([1, 1, 1])
            with col1:
                st.button("Prev", key="prev", on_click=lambda: st.session_state.update(
                    {"page_number": st.session_state.page_number - 1}),
                    disabled=st.session_state.page_number == 0
                )

            with col2:
                st.markdown(
                    f"<div font-size: 18px;'>Page <b>{st.session_state.page_number + 1}</b></div>",
                    unsafe_allow_html=True
                )

            with col3:
                st.button("Next", key="next", on_click=lambda: st.session_state.update(
                    {"page_number": st.session_state.page_number + 1})
                )
    
    with github_repo_explorer:
        skip_count = st.session_state.page_number * PAGE_SIZE
        github_list = driver.get_github_list()
        github_search = st.selectbox("Select GitHub Repo", options=github_list, key="github_search")

        if "page_number" not in st.session_state:
            st.session_state.page_number = 0

        if "previous_github" not in st.session_state:
            st.session_state.previous_github = github_search

        # Check if ecosystem changed
        if github_search != st.session_state.github_search:
            st.session_state.page_number = 0
            st.session_state.github_search = github_search

        if github_search == "":
            github_vuln = driver.get_vulnerabilities_by_github(skip=skip_count, limit=PAGE_SIZE)
            if github_vuln.empty:
                st.warning("No vulnerabilities found.")
        else:
            github_vuln = driver.get_specific_vulnerabilities_by_github(github_search, skip=skip_count, limit=PAGE_SIZE)
            if github_vuln.empty:
                st.warning("No vulnerabilities found.")
        for _, row in github_vuln.iterrows():
            with st.container():
                st.markdown(f"""
                <div style="border:1px solid #ccc; padding:10px; border-radius:8px; margin-bottom:10px;">
                    <h5>GitHub Repo: <span style="color: #007BFF;">{row['name']}</span> </h5>
                <h5> Minimal Affected Versions:</h5>
                <div style="position: absolute; top: 10px; right: 10px;"> ID: {row['ID']}</div>
                    <ul style="padding-left: 20px;">
                        {''.join([f'<li>{version}</li>' for version in row['minimal']])}
                    </ul>
                    <h5>Summary:</h5>
                    <p>{row['summary']}</p>
                    <h5>Language Breakdown:</h5>
                    <ul style="padding-left: 20px;">
                    {', '.join([f"{lang}: {percentage:.1f}%" for lang, percentage in sorted(json.loads(row['breakdown']).items(), key=lambda x: x[1], reverse=True)[:5]])}
                    </ul>
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

if __name__ == "__main__":
    run()