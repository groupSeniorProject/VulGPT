import streamlit as st


def run():
    st.title("VulGPT")
    code = st.file_uploader(label="Upload", type=["py","java","c","js"])
    
    def code_lanaguge(f_name):
        if f_name.endswith('.py'):
            return "python"
        elif f_name.endswith('.java'):
            return "java"
        elif f_name.endswith('.c'):
            return "c"
        elif f_name.endswith('.js'):
            return "javascript"
        else:
            return "text"
        
    if code is not None:
        c_content = code.read().decode('utf-8')
        language = code_lanaguge(code.name)
        with st.expander("Code:"):
            st.code(c_content, language=language)


if __name__ == "__main__":
    run()