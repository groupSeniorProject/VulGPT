import streamlit as st
from streamlit_manager import Neo4jManager

def run():
    driver = Neo4jManager()

    if driver is not None:
        with st.container():
            total_nodes = driver.get_total_node_vulns("MATCH (n) RETURN COUNT(n) as total_nodes", 'total_nodes')
            st.markdown(f"""
            <div style="display: flex; justify-content: center; align-items: center; font-size:20px;">
                <p>Total Vulnerabilities: {total_nodes}</p>
            </div>
            """, unsafe_allow_html=True)


        curr_display = st.sidebar.selectbox("Select Chart", options=["Pie Chart", "Bar Graph"])
        
        if curr_display == "Pie Chart":
            driver.unique_eco_pie_chart()
        elif curr_display == "Bar Graph":
            driver.unique_eco_bar_chart()

if __name__ == "__main__":
    run()