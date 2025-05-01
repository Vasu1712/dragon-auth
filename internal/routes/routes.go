package routes

import (
	"context"
	"encoding/json"
	"text/template"

	"net/http"

	"github.com/Vasu1712/dragon-auth/internal/config"
	"github.com/Vasu1712/dragon-auth/internal/handlers"
	"github.com/Vasu1712/dragon-auth/internal/models"
	"github.com/gorilla/mux"
	"github.com/valkey-io/valkey-go"
)

// SetupRouter configures and returns the application router
func SetupRouter(client valkey.Client, config *config.Config) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	
	// Create auth handler
	authHandler := handlers.NewAuthHandler(client, config)

	//tenant router
	router.Use(handlers.TenantMiddleware)
	
	// Public routes
	router.HandleFunc("/api/auth/register", authHandler.Register).Methods("POST")
	router.HandleFunc("/api/auth/login", authHandler.Login).Methods("POST")
	
	// Health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")
	
	// Protected routes
	protected := router.PathPrefix("/api").Subrouter()
	protected.Use(handlers.AuthMiddleware(client, config))
	
	protected.HandleFunc("/auth/logout", authHandler.Logout).Methods("POST")
	protected.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		// Simple handler to return the authenticated user
		user := r.Context().Value("user")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}).Methods("GET")
	
	// Create admin subrouter with additional admin middleware
	adminRouter := router.PathPrefix("/admin").Subrouter()
    adminRouter.Use(handlers.AdminMiddleware(client, config))
	
	// Admin dashboard - List all users
	adminRouter.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		tenantID := r.Context().Value("tenant_id").(string)

		// Get all user keys from Valkey
		userKeys, err := client.Do(ctx, client.B().Keys().Pattern(tenantID+":user:*").Build()).AsStrSlice()
		if err != nil {
			http.Error(w, "Failed to fetch user keys: "+err.Error(), http.StatusInternalServerError)
			return
		}
		
		users := make([]models.User, 0, len(userKeys))
		
		// Fetch each user's data
		for _, key := range userKeys {
			userJSON, err := client.Do(ctx, client.B().Get().Key(key).Build()).ToString()
			if err != nil {
				continue // Skip users that can't be retrieved
			}
			
			var user models.User
			if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
				continue // Skip users that can't be parsed
			}
			
			// Add user to the list
			users = append(users, user)
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total": len(users),
			"users": users,
		})
	}).Methods("GET")
	
	// Admin dashboard - Get user by email
	adminRouter.HandleFunc("/users/{email}", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		vars := mux.Vars(r)
		email := vars["email"]
		
		userKey := "user:" + email
		exists, err := client.Do(ctx, client.B().Exists().Key(userKey).Build()).AsInt64()
		if err != nil || exists == 0 {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		
		userJSON, err := client.Do(ctx, client.B().Get().Key(userKey).Build()).ToString()
		if err != nil {
			http.Error(w, "Failed to fetch user data", http.StatusInternalServerError)
			return
		}
		
		var user models.User
		if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
			http.Error(w, "Failed to parse user data", http.StatusInternalServerError)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}).Methods("GET")
	
	// Admin dashboard - List all active tokens
	adminRouter.HandleFunc("/tokens", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		
		tokenKeys, err := client.Do(ctx, client.B().Keys().Pattern("token:*").Build()).AsStrSlice()
		if err != nil {
			http.Error(w, "Failed to fetch tokens", http.StatusInternalServerError)
			return
		}
		
		tokensMap := make(map[string]string, len(tokenKeys))
		
		// Get token -> userID mapping
		for _, key := range tokenKeys {
			userID, err := client.Do(ctx, client.B().Get().Key(key).Build()).ToString()
			if err != nil {
				continue
			}
			
			// Extract token from key (remove "token:" prefix)
			token := key[6:] // Assumes "token:" is the prefix
			tokensMap[token] = userID
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total":  len(tokensMap),
			"tokens": tokensMap,
		})
	}).Methods("GET")
	
	// Admin dashboard - Get database stats
	adminRouter.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		
		// Get Valkey database statistics
		info, err := client.Do(ctx, client.B().Info().Build()).AsStrSlice()
		if err != nil {
			http.Error(w, "Failed to fetch database info", http.StatusInternalServerError)
			return
		}
		
		// Count users
		userCount, err := client.Do(ctx, client.B().Keys().Pattern("user:*").Build()).AsStrSlice()
		if err != nil {
			http.Error(w, "Failed to count users", http.StatusInternalServerError)
			return
		}
		
		// Count tokens
		tokenCount, err := client.Do(ctx, client.B().Keys().Pattern("token:*").Build()).AsStrSlice()
		if err != nil {
			http.Error(w, "Failed to count tokens", http.StatusInternalServerError)
			return
		}
		
		// Parse raw info into a map for easier consumption
		infoMap := make(map[string]string)
		currentSection := ""
		
		for _, line := range info {
			if line == "" {
				continue
			}
			
			// Section headers in Redis INFO start with #
			if line[0] == '#' {
				currentSection = line[2:] // Remove "# " prefix
				continue
			}
			
			// Find key-value separator
			colonPos := -1
			for i, char := range line {
				if char == ':' {
					colonPos = i
					break
				}
			}
			
			if colonPos != -1 {
				key := line[:colonPos]
				value := line[colonPos+1:]
				infoMap[currentSection+"."+key] = value
			}
		}
		
		// Prepare response
		stats := map[string]interface{}{
			"users":  len(userCount),
			"tokens": len(tokenCount),
			"server": map[string]string{
				"version":       infoMap["server.redis_version"],
				"uptime_days":   infoMap["server.uptime_in_days"],
				"connected_clients": infoMap["clients.connected_clients"],
				"used_memory":   infoMap["memory.used_memory_human"],
				"total_commands_processed": infoMap["stats.total_commands_processed"],
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	}).Methods("GET")

	// Admin dashboard - Delete user by email
	adminRouter.HandleFunc("/users/{email}", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		vars := mux.Vars(r)
		email := vars["email"]
		
		userKey := "user:" + email
		
		// Check if user exists
		exists, err := client.Do(ctx, client.B().Exists().Key(userKey).Build()).AsInt64()
		if err != nil || exists == 0 {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		
		// Get user data for cleanup (we need the user ID)
		userJSON, err := client.Do(ctx, client.B().Get().Key(userKey).Build()).ToString()
		if err != nil {
			http.Error(w, "Failed to fetch user data", http.StatusInternalServerError)
			return
		}
		
		var user models.User
		if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
			http.Error(w, "Failed to parse user data", http.StatusInternalServerError)
			return
		}
		
		// Delete user's tokens (find and delete all tokens for this user)
		tokenKeys, err := client.Do(ctx, client.B().Keys().Pattern("token:*").Build()).AsStrSlice()
		if err == nil {
			for _, tokenKey := range tokenKeys {
				userID, err := client.Do(ctx, client.B().Get().Key(tokenKey).Build()).ToString()
				if err == nil && userID == user.ID {
					client.Do(ctx, client.B().Del().Key(tokenKey).Build())
				}
			}
		}
		
		// Delete user ID mapping
		err = client.Do(ctx, client.B().Del().Key("userid:"+user.ID).Build()).Error()
		if err != nil {
			http.Error(w, "Error deleting user mapping", http.StatusInternalServerError)
			return
		}
		
		// Delete user record
		err = client.Do(ctx, client.B().Del().Key(userKey).Build()).Error()
		if err != nil {
			http.Error(w, "Error deleting user", http.StatusInternalServerError)
			return
		}
		
		// Return success with no content
		w.WriteHeader(http.StatusNoContent)
	}).Methods("DELETE")


	adminRouter.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		tenantID := r.Context().Value("tenant_id").(string)
		projectName := "Default Project"

		projectKey := tenantID + ":project:info"
		projectJSON, err := client.Do(ctx, client.B().Get().Key(projectKey).Build()).ToString()
		if err == nil {
			var projectInfo map[string]interface{}
			if json.Unmarshal([]byte(projectJSON), &projectInfo) == nil {
				if name, ok := projectInfo["name"].(string); ok && name != "" {
					projectName = name
				}
			}
		}
		// Get all user keys from Valkey
		userKeys, err := client.Do(ctx, client.B().Keys().Pattern(tenantID+":user:*").Build()).AsStrSlice()

		if err != nil {
			http.Error(w, "Failed to fetch user keys: "+err.Error(), http.StatusInternalServerError)
			return
		}
		
		users := make([]models.User, 0, len(userKeys))
		
		// Fetch each user's data
		for _, key := range userKeys {
			userJSON, err := client.Do(ctx, client.B().Get().Key(key).Build()).ToString()
			if err != nil {
				continue // Skip users that can't be retrieved
			}
			
			var user models.User
			if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
				continue // Skip users that can't be parsed
			}
			
			// Add user to the list
			users = append(users, user)
		}
		
		// Create a template with proper HTML structure
		tmpl := template.Must(template.New("dashboard").Parse(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>Admin Dashboard - {{.ProjectName}}</title>
			<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
			<style>
				body { font-family: Arial, sans-serif; margin: 20px; }
				table { border-collapse: collapse; width: 100%; }
				th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
				th { background-color: #f2f2f2; }
				tr:nth-child(even) { background-color: #f9f9f9; }
				.icon-btn { cursor: pointer; margin: 0 5px; font-size: 16px; }
				.fa-edit { color: #4CAF50; }
				.fa-trash-alt { color: #f44336; }
				h1, h2 { color: #333; }
				.project-name { color: #0066cc; font-weight: bold; }
			</style>
		</head>
		<body>
			<h1>Dragon-auth Admin Dashboard</h1>
			<h2>Project: <span class="project-name">{{.ProjectName}}</span></h2>
			
			<table id="userTable">
				<thead>
					<tr>
						<th>Name</th>
						<th>E-mail</th>
						<th>User ID</th>
						<th>Created At</th>
						<th>Login At</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{{if len .Users}}
						{{range .Users}}
						<tr id="user-row-{{.ID}}">
							<td>{{if and .FirstName .LastName}}{{.FirstName}} {{.LastName}}{{else}}{{.Email}}{{end}}</td>
							<td>{{.Email}}</td>
							<td>{{.ID}}</td>
							<td>{{.CreatedAt.Format "3:04 PM Jan 2, 2006"}}</td>
							<td>{{.UpdatedAt.Format "3:04 PM Jan 2, 2006"}}</td>
							<td>
								<i class="fas fa-edit icon-btn" onclick="editUser('{{.ID}}')"></i>
								<i class="fas fa-trash-alt icon-btn" onclick="deleteUser('{{.ID}}', '{{.Email}}')"></i>
							</td>
						</tr>
						{{end}}
					{{else}}
						<tr><td colspan="6">No users found</td></tr>
					{{end}}
				</tbody>
			</table>
			
			<script>
			function editUser(id) {
				// Edit functionality
				console.log("Edit user:", id);
			}
			
			function deleteUser(id, email) {
				// Confirm deletion
				if (!confirm("Are you sure you want to delete user: " + email + "?")) {
					return;
				}
				
				// Send delete request
				fetch('/admin/users/' + email, {
					method: 'DELETE',
					headers: {
						'Content-Type': 'application/json'
					}
				})
				.then(response => {
					if (!response.ok) {
						throw new Error('Failed to delete user: ' + response.status);
					}
					// On success, remove the row from the table
					const row = document.getElementById('user-row-' + id);
					if (row) {
						row.remove();
					}
					alert("User deleted successfully");
				})
				.catch(error => {
					console.error("Error deleting user:", error);
					alert("Error deleting user: " + error.message);
				});
			}
			</script>
		</body>
		</html>
		`))

		
		// Execute the template with the users data
		w.Header().Set("Content-Type", "text/html")
		data := struct {
			ProjectName string
			Users       []models.User
		}{
			ProjectName: projectName,
			Users:       users,
		}
		
		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
		}
	}).Methods("GET")
	
	

	return router
}
