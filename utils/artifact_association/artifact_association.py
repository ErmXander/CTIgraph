from openai import OpenAI
import json
import os
import re
import argparse

VECTOR_STORE_ID = "vs_6863ef7fb2a08191b1f2f21ed504aa01"

class LLM_associator:
    """
    Allows to automatically associate libraries used by pods to D3FEND Digital Artifacts

    Args:
        api_key: OpenAI API key; if not provided defaults to env variable OPENAI_API_KEY
    """

    def __init__(self, api_key=os.environ.get("OPENAI_API_KEY")):
        self.client = OpenAI(api_key=api_key)

    def create_store(self, store_name):
        """
        Creates a vector_store and returns its metadata
        """
        try:
            vector_store = self.client.vector_stores.create(name=store_name)
            metadata = {
                "id": vector_store.id,
                "name": vector_store.name,
                "created_at": vector_store.created_at,
                "expires": vector_store.expires_after
            }
            print(metadata)
            return metadata
        except Exception as e:
            print(f"Error creating the vector_store: {e}")
            return {}
        
    def upload_files(self, file_path, vector_store_id):
        """"
        Uploads a file to a vector_store
        """
        file_name = os.path.basename(file_path)
        try:
            file_response = self.client.files.create(file=open(file_path, "rb"), purpose="assistants")
            attach_response = self.client.vector_stores.files.create(vector_store_id=vector_store_id, file_id=file_response.id)
            print("Successfully uploaded file to vector_store")
        except Exception as e:
            print(f"Error uploading {file_name}: {e}")

    def _get_llm_response(self, lib_name):
        """
        Uses an LLM (gpt-40-mini) to obtain the artifacts associated with a library.
        The model uses RAG by searching into the vector_store containing the embeddings of the DAO knowledge base.
        The model can search the internet to understand the use of the provided library.

        Args:
            lib_name: name of the library for which to perform association.
        """   
        example_json = {
            "artifacts": [
                {"id": "artifact1"},
                {"id": "artifact2"},
                {"id": "artifact3"}
            ]}
        query=f"""
            Given the library {lib_name}, use your knowledge of MITRE's Digital Artifact Ontology
            to map the library to the appropriate artifacts.
        """
        instructions=f"""
            You are a cybersecurity analyst with extensive knowledge of MITRE's Digital Artifact Ontology.
            Limit your web search only to the official websites of the libraries and Github.
            Associate as many artifacts as you think appropriate.
            The output must include only the JSON following the example: {json.dumps(example_json)}.
        """
        response = self.client.responses.create(
            model="gpt-4o-mini",
            instructions=instructions,
            input=query,
            tools=[
                {
                    "type": "file_search",
                    "vector_store_ids": [VECTOR_STORE_ID]
                },
                {
                    "type":"web_search_preview"
                }
            ],
            temperature=0
        )
        return response
    
    def get_artifacts_for_library(self, lib_name, full_response=False):
        """
        Obtains a response from the LLM and post-processes it.

        Args:
            lib_name: name of the library for which to perform association.
            full_response: returns the whole llm response.
        Returns:
            an object containing the associated artifacts in the form:
            {
                "artifacts": [
                    {"id": "art1"},
                    {"id": "art2"},
                    ...
                ]
            }
            The full LLM response if required.
        """
        try:
            response = self._get_llm_response(lib_name)
            text = response.output[1].content[0].text
            artifacts = re.search(r'```json\n(.*?)\n```', text, re.DOTALL).group(1)
            artifacts = json.loads(artifacts)
            if full_response:
                return artifacts, full_response
            return artifacts
        except Exception as e:
            print(f"Error obtaining artifacts: {e}")
            if full_response:
                return {}, full_response
            return {}
        

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("lib_name", help="Name of the library")
    parser.add_argument("-r", "--response", action="store_true", help="Also return the full llm response")
    parser.add_argument("-k", "--key", help="Specify the OpenAI API KEY to use")
    args = parser.parse_args()

    associator = LLM_associator(args.key)
    artifacts = associator.get_artifacts_for_library(args.lib_name)
    print(json.dumps(artifacts, indent=2))

if __name__ == '__main__':
    main()
