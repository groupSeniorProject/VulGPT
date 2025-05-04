import streamlit as st
from streamlit_manager import Neo4jManager

def main():
    driver = Neo4jManager()
    PAGE_SIZE = 10

    with st.spinner("Analysis Overview"):
        very_promising = driver.get_llm_very_promising()
        not_promising = driver.get_llm_not_promising()
        slightly_promising = driver.get_llm_slightly_promising()
        with st.container():
                st.markdown(f"""
                <div style="display: flex; justify-content: center; align-items: center; border:1px solid #ccc; padding:10px; border-radius:8px; margin-bottom:10px; font-size:20px;
                            position: sticky">
                    <p>
                        <span style="color: red;"> Not Promising: {not_promising}</span> |
                        <span style="color: yellow;">Slightly Promising: {slightly_promising}</span> |
                        <span style="color: green;">Very Promising: {very_promising}</span>
                    </p>
                </div>
                """, unsafe_allow_html=True)

    if "page_number" not in st.session_state:
        st.session_state.page_number = 0

    skip_count = st.session_state.page_number * PAGE_SIZE

    llm_df = driver.get_llm_response(skip=skip_count, limit=PAGE_SIZE)

    with st.spinner("LLM Analysis..."):
        for _, row in llm_df.iterrows():
            with st.container():
                st.markdown(f"""
                <div style="border:1px solid #ccc; padding:10px; border-radius:8px; margin-bottom:10px;">
                    <p>Headline: {row['headline']}</p>
                    <p>Analysis: {row['analysis']}</p>
                    <p>Funtions: {row['funtions']}</p>
                    <p>Filenames: {row['filenames']}</p>
                    <p>Classification: {row['classification']}</p>
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
    main()