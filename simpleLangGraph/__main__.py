import openai
from flask import Flask, request, jsonify
import langgraph
from langgraph.agents import WebSearchAgent
import os
from dotenv import load_dotenv

# Load OpenAI API Key from .env file
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

app = Flask(__name__)

class WebSearchLangGraphAgent:
    def __init__(self):
        self.agent = WebSearchAgent(
            search_engine='google',
            max_results=5,
            verbose=False
        )

    def search_with_validation(self, query, max_retries=3):
        attempts = 0
        
        while attempts < max_retries:
            results = self.agent.search(query)
            response_text = self.summarize_results(results)
            
            if self.model_meets_expectation(response_text):
                return response_text
            
            query = self.adjust_query(query)
            attempts += 1
        
        return "I cannot find the right answer."

    def summarize_results(self, results):
        return " ".join(result['snippet'] for result in results)
    
    def model_meets_expectation(self, response_text):
        # Use OpenAI GPT to determine if the response meets expectations
        prompt = f"Does the following response answer the user query accurately? Respond with 'meets_expectation' or 'not_meet_expectation'.\n\nResponse:\n{response_text}"
        
        response = openai.Completion.create(
            model="gpt-3.5-turbo",
            prompt=prompt,
            max_tokens=10,
            temperature=0.0
        )
        
        prediction = response.choices[0].text.strip().lower()
        return prediction == "meets_expectation"

    def adjust_query(self, query):
        return query + " more details"

# Initialize the agent with OpenAI model
agent = WebSearchLangGraphAgent()

@app.route("/search", methods=["POST"])
def search_query():
    data = request.get_json()
    
    if not data or "query" not in data:
        return jsonify({"error": "Query cannot be empty."}), 400
    
    query = data["query"]
    response = agent.search_with_validation(query)
    
    return jsonify({"query": query, "response": response})

if __name__ == "__main__":
    app.run(debug=True)
