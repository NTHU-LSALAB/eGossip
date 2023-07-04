package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// Set new node
func (nl *NodeList) SetNodeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Can't read request body", http.StatusBadRequest)
			return
		}

		fmt.Printf("Request Body: %s\n", string(body))

		var node Node
		err = json.Unmarshal(body, &node)
		if err != nil {
			http.Error(w, "Can't parse JSON", http.StatusBadRequest)
			return
		}

		// Update the node
		nl.Set(node) // Assuming "Set" is a method on NodeList

		// Write response
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte("Node list updated successfully.\n"))
		if err != nil {
			log.Println("Error writing response")
			return
		}

		log.Println("[Control]: Node list updated successfully.")
	}
}

// Dump node list.
func (nl *NodeList) ListNodeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		// Get the nodes
		nodes := nl.Get() // Assuming "Get" is a method on NodeList

		// Set the Content-Type header to indicate a JSON response
		w.Header().Set("Content-Type", "application/json")

		// Encode the nodes as JSON and write the response
		err := json.NewEncoder(w).Encode(nodes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
