package routes

import (
    "context"
    "encoding/json"
    "html/template"
    "log"
    "net/http"

    "github.com/Vasu1712/dragon-auth/internal/config"
    "github.com/Vasu1712/dragon-auth/internal/handlers"
    "github.com/Vasu1712/dragon-auth/internal/models"
    "github.com/Vasu1712/dragon-auth/pkg/whatsapp"
    "github.com/gorilla/mux"
    "github.com/valkey-io/valkey-go"
)

// SetupRouter configures and returns the application router
func SetupRouter(client valkey.Client, cfg *config.Config) *mux.Router {
    router := mux.NewRouter().StrictSlash(true)

    // Create auth handler
    authHandler := handlers.NewAuthHandler(client, cfg)

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
    protected.Use(handlers.AuthMiddleware(client, cfg))
    protected.HandleFunc("/auth/logout", authHandler.Logout).Methods("POST")
    protected.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
        user := r.Context().Value("user")
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(user)
    }).Methods("GET")

    // OTP routes
    whatsappClient := whatsapp.NewClient(
        cfg.WhatsAppAPIKey,
        cfg.WhatsAppBaseURL,
        cfg.WhatsAppPhoneID,
        cfg.WhatsAppBusinessID,
    )
    otpHandler := handlers.NewOTPHandler(client, cfg, whatsappClient)
    router.HandleFunc("/api/auth/request-otp", otpHandler.RequestOTP).Methods("POST")
    router.HandleFunc("/api/auth/login-with-otp", otpHandler.VerifyOTP).Methods("POST")

    // Admin subrouter with RBAC
    adminRouter := router.PathPrefix("/admin").Subrouter()
    adminRouter.Use(handlers.AdminMiddleware(client, cfg))

    // ---------- Admin JSON APIs ----------

    // Change User Role (SUPERADMIN ONLY)
    adminRouter.HandleFunc("/users/{email}/role", func(w http.ResponseWriter, r *http.Request) {
        ctx := context.Background()
        vars := mux.Vars(r)
        email := vars["email"]

        // Check if requester is superadmin
        isSuper := false
        if v := r.Context().Value("is_superadmin"); v != nil {
            isSuper = v.(bool)
        }

        if !isSuper {
            http.Error(w, "Only Superadmin can change user roles", http.StatusForbidden)
            return
        }

        // Parse body
        var req struct {
            Role    string `json:"role"`
            Project string `json:"project"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Invalid request body", http.StatusBadRequest)
            return
        }

        if req.Role != "admin" && req.Role != "user" {
            http.Error(w, "Invalid role. Must be 'admin' or 'user'", http.StatusBadRequest)
            return
        }
        if req.Project == "" {
            http.Error(w, "Project is required", http.StatusBadRequest)
            return
        }

        userKey := req.Project + ":user:" + email
        
        // Fetch existing user
        userJSON, err := client.Do(ctx, client.B().Get().Key(userKey).Build()).ToString()
        if err != nil {
            http.Error(w, "User not found or database error", http.StatusNotFound)
            return
        }

        var user models.User
        if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
            http.Error(w, "Database data corruption", http.StatusInternalServerError)
            return
        }

        // Update role
        user.Role = req.Role

        // Save back to DB
        updatedJSON, _ := json.Marshal(user)
        err = client.Do(ctx, client.B().Set().Key(userKey).Value(string(updatedJSON)).Build()).Error()
        if err != nil {
            http.Error(w, "Failed to update user role", http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(user)
    }).Methods("PUT")


    // List users (project-aware, superadmin can filter by project)
    adminRouter.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
        ctx := context.Background()

        // user and is_superadmin are set by AuthMiddleware + AdminMiddleware
        u, _ := r.Context().Value("user").(models.User)
        isSuper := false
        if v := r.Context().Value("is_superadmin"); v != nil {
            isSuper = v.(bool)
        }

        projectFilter := r.URL.Query().Get("project")

        // For admins: limit to their project namespace.
        // For superadmin: scan all projects.
        var keyPattern string
        if isSuper {
            keyPattern = "*:user:*"
        } else {
            if u.Project == "" {
                http.Error(w, "No project associated with admin user", http.StatusBadRequest)
                return
            }
            keyPattern = u.Project + ":user:*"
        }

        userKeys, err := client.Do(ctx, client.B().Keys().Pattern(keyPattern).Build()).AsStrSlice()
        if err != nil {
            http.Error(w, "Failed to fetch user keys: "+err.Error(), http.StatusInternalServerError)
            return
        }

        users := make([]models.UserResponse, 0, len(userKeys))
        projectSet := make(map[string]struct{})

        for _, key := range userKeys {
            userJSON, err := client.Do(ctx, client.B().Get().Key(key).Build()).ToString()
            if err != nil {
                continue
            }

            var uRec models.User
            if err := json.Unmarshal([]byte(userJSON), &uRec); err != nil {
                continue
            }

            // defensively enforce project for non-superadmin
            if !isSuper && uRec.Project != u.Project {
                continue
            }

            // optional project filter for superadmin/admin
            if projectFilter != "" && uRec.Project != projectFilter {
                continue
            }

            if uRec.Project != "" {
                projectSet[uRec.Project] = struct{}{}
            }

            users = append(users, models.UserResponse{
                ID:        uRec.ID,
                Email:     uRec.Email,
                FirstName: uRec.FirstName,
                LastName:  uRec.LastName,
                Role:      uRec.Role,
                Project:   uRec.Project,
                CreatedAt: uRec.CreatedAt,
                UpdatedAt: uRec.UpdatedAt,
            })
        }

        projects := make([]string, 0, len(projectSet))
        for p := range projectSet {
            projects = append(projects, p)
        }

        resp := map[string]interface{}{
            "total":    len(users),
            "users":    users,
            "projects": projects,
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
    }).Methods("GET")

    // Get user by email within caller's project (superadmin can override via query if needed)
    adminRouter.HandleFunc("/users/{email}", func(w http.ResponseWriter, r *http.Request) {
        ctx := context.Background()
        vars := mux.Vars(r)
        email := vars["email"]

        u, _ := r.Context().Value("user").(models.User)
        isSuper := false
        if v := r.Context().Value("is_superadmin"); v != nil {
            isSuper = v.(bool)
        }

        project := u.Project
        if isSuper {
            // allow ?project=... override for superadmin
            if p := r.URL.Query().Get("project"); p != "" {
                project = p
            }
        }
        if project == "" {
            http.Error(w, "Project required to fetch user", http.StatusBadRequest)
            return
        }

        userKey := project + ":user:" + email
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

    // List all active tokens (project-agnostic; you can later project-scope if desired)
    adminRouter.HandleFunc("/tokens", func(w http.ResponseWriter, r *http.Request) {
        ctx := context.Background()

        tokenKeys, err := client.Do(ctx, client.B().Keys().Pattern("*:token:*").Build()).AsStrSlice()
        if err != nil {
            http.Error(w, "Failed to fetch tokens", http.StatusInternalServerError)
            return
        }

        tokensMap := make(map[string]string, len(tokenKeys))
        for _, key := range tokenKeys {
            userID, err := client.Do(ctx, client.B().Get().Key(key).Build()).ToString()
            if err != nil {
                continue
            }
            tokensMap[key] = userID
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "total":  len(tokensMap),
            "tokens": tokensMap,
        })
    }).Methods("GET")

    // Database stats (global)
    adminRouter.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
        ctx := context.Background()

        info, err := client.Do(ctx, client.B().Info().Build()).AsStrSlice()
        if err != nil {
            http.Error(w, "Failed to fetch database info", http.StatusInternalServerError)
            return
        }

        userCount, err := client.Do(ctx, client.B().Keys().Pattern("*:user:*").Build()).AsStrSlice()
        if err != nil {
            http.Error(w, "Failed to count users", http.StatusInternalServerError)
            return
        }

        tokenCount, err := client.Do(ctx, client.B().Keys().Pattern("*:token:*").Build()).AsStrSlice()
        if err != nil {
            http.Error(w, "Failed to count tokens", http.StatusInternalServerError)
            return
        }

        infoMap := make(map[string]string)
        currentSection := ""
        for _, line := range info {
            if line == "" {
                continue
            }
            if line[0] == '#' {
                currentSection = line[2:]
                continue
            }
            colonPos := -1
            for i, c := range line {
                if c == ':' {
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

        stats := map[string]interface{}{
            "users":  len(userCount),
            "tokens": len(tokenCount),
            "server": map[string]string{
                "version":                infoMap["server.redis_version"],
                "uptime_days":            infoMap["server.uptime_in_days"],
                "connected_clients":      infoMap["clients.connected_clients"],
                "used_memory":            infoMap["memory.used_memory_human"],
                "total_commands_processed": infoMap["stats.total_commands_processed"],
            },
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(stats)
    }).Methods("GET")

    // Delete user by email (within project)
    adminRouter.HandleFunc("/users/{email}", func(w http.ResponseWriter, r *http.Request) {
        ctx := context.Background()
        vars := mux.Vars(r)
        email := vars["email"]

        u, _ := r.Context().Value("user").(models.User)
        isSuper := false
        if v := r.Context().Value("is_superadmin"); v != nil {
            isSuper = v.(bool)
        }

        project := u.Project
        if isSuper {
            if p := r.URL.Query().Get("project"); p != "" {
                project = p
            }
        }
        if project == "" {
            http.Error(w, "Project required to delete user", http.StatusBadRequest)
            return
        }

        userKey := project + ":user:" + email

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

        // Delete tokens for this user across all projects (simple but global)
        tokenKeys, err := client.Do(ctx, client.B().Keys().Pattern("*:token:*").Build()).AsStrSlice()
        if err == nil {
            for _, tKey := range tokenKeys {
                userID, err := client.Do(ctx, client.B().Get().Key(tKey).Build()).ToString()
                if err == nil && userID == user.ID {
                    client.Do(ctx, client.B().Del().Key(tKey).Build())
                }
            }
        }

        // Delete user ID mapping for this project
        if err := client.Do(ctx, client.B().Del().Key(project+":userid:"+user.ID).Build()).Error(); err != nil {
            http.Error(w, "Error deleting user mapping", http.StatusInternalServerError)
            return
        }

        if err := client.Do(ctx, client.B().Del().Key(userKey).Build()).Error(); err != nil {
            http.Error(w, "Error deleting user", http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusNoContent)
    }).Methods("DELETE")

    adminRouter.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
        u, _ := r.Context().Value("user").(models.User)
        isSuper := false
        if v := r.Context().Value("is_superadmin"); v != nil {
            isSuper = v.(bool)
        }

        tmpl := template.Must(template.New("dashboard").Parse(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>Dragon Auth Admin Dashboard</title>
			<style>
				body { font-family: Arial, sans-serif; margin: 20px; }
				h1 { color: #333; }
				.card { background: #f9f9f9; border-radius: 5px; padding: 15px; margin-bottom: 15px; }
				table { width: 100%; border-collapse: collapse; }
				th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
				th { background-color: #f2f2f2; }
				.button { background: #4CAF50; color: white; padding: 8px 14px; border: none; border-radius: 4px; cursor: pointer; }
				.delete-btn { background: #f44336; color: white; padding: 5px 10px; border: none; border-radius: 4px; cursor: pointer; }
				.filter-section { margin-bottom: 10px; }
				select { padding: 6px; border-radius: 4px; }
				.badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; background:#ff9800; color:#fff; margin-left:8px;}
			</style>
			<script>
				const isSuperAdmin = {{if .IsSuperAdmin}}true{{else}}false{{end}};

				async function loadUsers(project) {
					try {
						const token = localStorage.getItem('admin_token');
						if (!token) {
							document.getElementById('error').innerText = 'No admin token in localStorage.';
							return;
						}

						let url = '/admin/users';
						if (project) {
							url += '?project=' + encodeURIComponent(project);
						}

						const res = await fetch(url, {
							headers: { 'Authorization': 'Bearer ' + token }
						});

						if (!res.ok) {
							const text = await res.text();
							document.getElementById('error').innerText = 'Error: ' + text;
							return;
						}

						const data = await res.json();
						document.getElementById('error').innerText = '';

						const tbody = document.getElementById('usersTable');
						tbody.innerHTML = '';

						if (!data.users || data.users.length === 0) {
							tbody.innerHTML = '<tr><td colspan="6">No users found</td></tr>';
							document.getElementById('userCount').innerText = '0';
						} else {
							data.users.forEach(u => {
								const tr = document.createElement('tr');
								tr.innerHTML =
									'<td>' + (u.first_name || '') + ' ' + (u.last_name || '') + '</td>' +
									'<td>' + u.email + '</td>' +
									'<td>' + (u.role || '') + '</td>' +
									'<td>' + (u.project || '') + '</td>' +
									'<td>' + new Date(u.created_at).toLocaleString() + '</td>' +
									'<td><button class="delete-btn" onclick="deleteUser(\\'' + u.email + '\\', \'' + (u.project || '') + '\')">Delete</button></td>';
								tbody.appendChild(tr);
							});
							document.getElementById('userCount').innerText = data.total;
						}

						if (isSuperAdmin && data.projects) {
							const sel = document.getElementById('projectFilter');
							sel.innerHTML = '<option value="">All projects</option>';
							data.projects.forEach(p => {
								const opt = document.createElement('option');
								opt.value = p;
								opt.textContent = p;
								if (p === project) opt.selected = true;
								sel.appendChild(opt);
							});
							document.getElementById('filterSection').style.display = 'block';
						}

					} catch (err) {
						document.getElementById('error').innerText = 'Error: ' + err.message;
					}
				}

				function onProjectChange() {
					const p = document.getElementById('projectFilter').value;
					loadUsers(p);
				}

				async function deleteUser(email, project) {
					if (!confirm('Delete user ' + email + '?')) return;

					const token = localStorage.getItem('admin_token');
					if (!token) {
						alert('No admin token in localStorage.');
						return;
					}

					let url = '/admin/users/' + encodeURIComponent(email);
					if (project) {
						url += '?project=' + encodeURIComponent(project);
					}

					const res = await fetch(url, {
						method: 'DELETE',
						headers: { 'Authorization': 'Bearer ' + token }
					});

					if (res.ok) {
						alert('User deleted');
						const currentProject = document.getElementById('projectFilter') ? document.getElementById('projectFilter').value : '';
						loadUsers(currentProject);
					} else {
						const text = await res.text();
						alert('Failed to delete user: ' + text);
					}
				}

				window.onload = function() {
					loadUsers();
				};
			</script>
		</head>
		<body>
			<h1>Dragon Auth Admin Dashboard {{if .IsSuperAdmin}}<span class="badge">SUPERADMIN</span>{{end}}</h1>

			<div id="error" style="color:red;margin-bottom:10px;"></div>

			{{if .IsSuperAdmin}}
			<div id="filterSection" class="card filter-section" style="display:none;">
				<strong>Filter by project:</strong>
				<select id="projectFilter" onchange="onProjectChange()"></select>
			</div>
			{{end}}

			<div class="card">
				<h2>Users (<span id="userCount">0</span>)</h2>
				<table>
					<thead>
						<tr>
							<th>Name</th>
							<th>E-mail</th>
							<th>Role</th>
							<th>Project</th>
							<th>Created At</th>
							<th>Actions</th>
						</tr>
					</thead>
					<tbody id="usersTable">
						<tr><td colspan="6">Loading...</td></tr>
					</tbody>
				</table>
				<button class="button" onclick="loadUsers()">Refresh</button>
			</div>
		</body>
		</html>
		`))

        data := struct {
            IsSuperAdmin bool
            User         models.User
        }{
            IsSuperAdmin: isSuper,
            User:         u,
        }

        w.Header().Set("Content-Type", "text/html")
        if err := tmpl.Execute(w, data); err != nil {
            log.Println("template error:", err)
            http.Error(w, "Template execution error", http.StatusInternalServerError)
            return
        }
    }).Methods("GET")

    return router
}