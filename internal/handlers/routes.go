package handlers

import (
	"forum/config"
	"forum/internal/service"
	"forum/pkg/mids"
	"forum/pkg/sesm"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"
)

type userRateLimit struct {
	lastReq time.Time
	penalty time.Duration
}

type Routes struct {
	services       *service.Services
	tempCache      map[string]*template.Template
	sesm           *sesm.SessionManager
	logger         *log.Logger
	cfg            *config.Config
	userRateLimits map[string]userRateLimit
	rateMu         *sync.Mutex
}

func NewRouter(
	services *service.Services,
	sesm *sesm.SessionManager,
	logger *log.Logger,
	cfg *config.Config,
) *Routes {

	// Temporary cache for one-time template initialization and subsequent
	// storage in templates map
	tempCache, err := newTemplateCache()
	if err != nil {
		log.Fatalf("Error creating cached templates:%v", err)
	}

	return &Routes{
		services:       services,
		tempCache:      tempCache,
		sesm:           sesm,
		logger:         logger,
		cfg:            cfg,
		userRateLimits: make(map[string]userRateLimit),
		rateMu:         &sync.Mutex{},
	}
}

// NewRouter returns http.Handler type router with registered routes
func (r *Routes) Register() http.Handler {
	router := http.NewServeMux()

	// Serve static files
	fileServer := http.FileServer(http.Dir("./web/static/"))
	router.Handle("/static/", r.preventDirListing(http.StripPrefix("/static", fileServer)))

	// Dynamic middleware chain for routes that don't require authentication
	dynamic := mids.New(r.sesm.LoadAndSave, r.detectGuest)

	// GUEST MODE
	router.Handle("/", dynamic.ThenFunc(r.home))
	router.Handle("/sortByTags/", dynamic.ThenFunc(r.sortedByTag))
	router.Handle("/user/login", dynamic.ThenFunc(r.userLoginPost))
	router.Handle("/user/signup", dynamic.ThenFunc(r.userSignupPost))
	router.Handle("/post/view/", dynamic.ThenFunc(r.postView)) // postID at the end

	// EXTERNAL AUTH
	router.Handle("/login/google", dynamic.ThenFunc(r.googlelogin))
	router.Handle("/callbackGoogle", dynamic.ThenFunc(r.googleCallback))
	router.Handle("/login/github", dynamic.ThenFunc(r.githublogin))
	router.Handle("/callbackGithub", dynamic.ThenFunc(r.githubCallback))

	// Protected appends dynamic middleware chain and used for routes
	// that require authentication
	protected := dynamic.Append(r.requireAuthentication)

	// POST
	router.Handle("/post/myPosts", protected.ThenFunc(r.postsPersonal))
	router.Handle("/post/myReacted", protected.ThenFunc(r.postsReacted))
	router.Handle("/post/myCommented", protected.ThenFunc(r.postsCommented))
	router.Handle("/post/create", protected.ThenFunc(r.postCreate))
	router.Handle("/post/edit/", protected.ThenFunc(r.postEdit))         // postID at the end
	router.Handle("/post/delete/", protected.ThenFunc(r.postDelete))     // postID at the end
	router.Handle("/post/report/", protected.ThenFunc(r.postReport))     // postID at the end
	router.Handle("/post/reaction/", protected.ThenFunc(r.postReaction)) // postID at the end

	// COMMENT
	router.Handle("/post/comment/", protected.ThenFunc(r.commentCreate))            // postID at the end
	router.Handle("/post/comment/edit/", protected.ThenFunc(r.commentEdit))         // postID at the end
	router.Handle("/post/comment/reaction/", protected.ThenFunc(r.commentReaction)) // postID at the end
	router.Handle("/post/comment/delete/", protected.ThenFunc(r.commentDelete))     // commentID at the end
	router.Handle("/post/comment/report/", protected.ThenFunc(r.commentReport))     // commentID at the end

	// USER
	router.Handle("/user/promote", protected.ThenFunc(r.userPromote))
	router.Handle("/user/notifications", protected.ThenFunc(r.notifications))
	router.Handle("/user/deleteNotification/", protected.ThenFunc(r.deleteNotification)) // notificationID at the end
	router.Handle("/user/logout", protected.ThenFunc(r.userLogout))

	// ADMIN
	requireAdmin := protected.Append(r.requireAdminRights)

	router.Handle("/admin/requests", requireAdmin.ThenFunc(r.requests))
	router.Handle("/admin/reports", requireAdmin.ThenFunc(r.reports))                  // TODO
	router.Handle("/admin/promote/", requireAdmin.ThenFunc(r.promoteUser))             // userID at the end
	router.Handle("/admin/demote/", requireAdmin.ThenFunc(r.demoteUser))               // userID at the end
	router.Handle("/admin/rejectPromotion/", requireAdmin.ThenFunc(r.rejectPromotion)) // userID at the end
	router.Handle("/admin/rejectReport/", requireAdmin.ThenFunc(r.rejectReport))       // userID at the end
	router.Handle("/admin/users", requireAdmin.ThenFunc(r.users))
	router.Handle("/admin/tags", requireAdmin.ThenFunc(r.tags))
	router.Handle("/admin/tags/delete/", requireAdmin.ThenFunc(r.tagDelete)) // tagID at the end
	router.Handle("/admin/tags/create", requireAdmin.ThenFunc(r.tagCreate))
	router.Handle("/admin/dashboard", requireAdmin.ThenFunc(r.dashboard))

	// Standard middleware chain applied to router itself -> used in all routes
	standard := mids.New(r.recoverPanic, r.limitRate, r.secureHeaders)

	return standard.Then(router)
}
