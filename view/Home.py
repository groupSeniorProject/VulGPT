import streamlit as st
from streamlit_manager import Neo4jManager

def run():
    driver = Neo4jManager()

    if driver is not None:
        st.title("VulGPT")

        total_nodes = driver.get_total_node_vulns("MATCH (n) RETURN COUNT(n) as total_nodes", 'total_nodes')
        st.write(f"Total Vulnerabilities: {total_nodes}")


        curr_display = st.sidebar.selectbox("Select Chart", options=["Pie Chart", "Bar Graph"])
        
        if curr_display == "Pie Chart":
            driver.unique_eco_pie_chart()
        elif curr_display == "Bar Graph":
            driver.unique_eco_bar_chart()

if __name__ == "__main__":
    run()