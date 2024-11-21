package user

import (
	"errors"
	"forum/internal/entity"
	"forum/internal/repository/user"
	"forum/internal/validator"
	"github.com/cdipaolo/sentiment"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type IUserService interface {
	SaveUser(*entity.UserSignupForm) (int, error)
	Authenticate(*entity.UserLoginForm) (int, error)
	GetUsernameById(int) (string, error)
	GetUserByEmail(string) (entity.UserEntity, error)
	GetUserRole(int) (string, error)
	SendNotification(notification entity.Notification) error
	SendPromotion(userID int) error
	SendReport(report entity.Report) error
	DeleteReport(reportID int) error
	DeletePromotion(promotionID int) error
	GetRequests() (*[]entity.Request, error)
	GetReports() (*[]entity.Report, error)
	PromoteUser(userID int) error
	DemoteUser(userID int) error
	GetNotifications(userID int) (*[]entity.Notification, error)
	DeleteNotification(notificationID int) error
	GetUsers() (*[]entity.UserEntity, error)
	FindNotification(nType string, userFrom, userTo int) (int, error)
	GetNotificationsCount(userID int) (int, error)

	GetDashboardStats() (entity.DashboardStats, error)
}

type userService struct {
	userRepo user.IUserRepository
}

func NewUserService(u user.IUserRepository) *userService {
	return &userService{
		userRepo: u,
	}
}

var _ IUserService = (*userService)(nil)

func (us *userService) SaveUser(u *entity.UserSignupForm) (int, error) {
	if !IsRightSignUp(u) {
		return 0, entity.ErrInvalidFormData
	}

	// Check if used with that username doesn't already exist
	user, err := us.userRepo.GetByUsername(u.Username)
	if err != nil && !errors.Is(err, entity.ErrInvalidCredentials) {
		return 0, err
	}
	if user != (entity.UserEntity{}) && strings.EqualFold(u.Username, user.Username) {
		return 0, entity.ErrDuplicateUsername
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), 12)
	if err != nil {
		return 0, err
	}

	id, err := us.userRepo.Insert(*u, hashedPassword)
	if err != nil {
		switch {
		case errors.Is(err, entity.ErrDuplicateEmail):
			u.AddFieldError("email", "Email address is already in use")
			return 0, entity.ErrDuplicateEmail
		case errors.Is(err, entity.ErrDuplicateUsername):
			u.AddFieldError("username", "Username is already in use")
			return 0, entity.ErrDuplicateUsername
		default:
			return 0, err
		}
	}

	return id, nil
}

func (us *userService) Authenticate(u *entity.UserLoginForm) (int, error) {
	if !IsRightLogin(u) {
		return 0, entity.ErrInvalidFormData
	}

	var userFromDB entity.UserEntity
	var err error

	if validator.Matches(u.Identifier, EmailRX) {
		userFromDB, err = us.userRepo.GetByEmail(u.Identifier)
	} else {
		userFromDB, err = us.userRepo.GetByUsername(u.Identifier)
	}
	if err != nil {
		if errors.Is(err, entity.ErrInvalidCredentials) {
			u.AddNonFieldError("Email or password is incorrect")
			return 0, entity.ErrInvalidCredentials
		} else {
			return 0, err
		}
	}

	err = bcrypt.CompareHashAndPassword([]byte(userFromDB.Password), []byte(u.Password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			u.AddNonFieldError("Email or password is incorrect")
			return 0, entity.ErrInvalidCredentials
		} else {
			return 0, err
		}
	}

	return userFromDB.ID, nil
}

func (us *userService) GetUsernameById(userID int) (string, error) {
	return us.userRepo.GetUsernameByID(userID)
}

func (us *userService) GetUserByEmail(email string) (entity.UserEntity, error) {
	return us.userRepo.GetByEmail(email)
}

func (us *userService) GetUserRole(userID int) (string, error) {
	return us.userRepo.GetRole(userID)
}

func (us *userService) SendNotification(n entity.Notification) error {
	switch n.Type {
	case entity.PROMOTED:
		n.Content = "Congratulations! You've been promoted to a moderator!"
	case entity.DEMOTED:
		n.Content = "Oh, looks like you've been demoted from a moderator role :("
	case entity.POST_LIKE:
		n.Content = "Liked your post"
	case entity.POST_DISLIKE:
		n.Content = "Disliked your post"
	case entity.COMMENT_LIKE:
		n.Content = "Liked your comment"
	case entity.COMMENT_DISLIKE:
		n.Content = "Disliked your comment"
	case entity.COMMENTED:
		n.Content = "Left a comment on your post"
	case entity.REJECT_PROMOTION:
		n.Content = "Your promotion was rejected"
	case entity.REJECT_REPORT:
		n.Content = "Your report was rejected"
	case entity.DELETE_POST:
		n.Content = "Your post/posts was/were deleted" + n.Content
	case entity.DELETE_COMMENT:
		n.Content = "Your comment/comments was/were deleted" + n.Content
	default:
		return entity.ErrInvalidNotificaitonType
	}

	return us.userRepo.CreateNotification(n)
}

func (us *userService) SendPromotion(userID int) error {
	return us.userRepo.CreatePromotion(userID)
}

func (us *userService) SendReport(report entity.Report) error {
	return us.userRepo.CreateReport(report)
}

func (us *userService) DeleteReport(reportID int) error {
	return us.userRepo.DeleteReport(reportID)
}

func (us *userService) DeletePromotion(promotionID int) error {
	return us.userRepo.DeletePromotion(promotionID)
}

func (us *userService) GetRequests() (*[]entity.Request, error) {
	return us.userRepo.GetRequests()
}

func (us *userService) GetReports() (*[]entity.Report, error) {
	return us.userRepo.GetReports()
}

func (us *userService) GetNotifications(userID int) (*[]entity.Notification, error) {
	return us.userRepo.GetNotifications(userID)
}

func (us *userService) GetNotificationsCount(userID int) (int, error) {
	return us.userRepo.GetNotificationsCount(userID)
}

func (us *userService) PromoteUser(userID int) error {
	return us.userRepo.Promote(userID)
}

func (us *userService) DemoteUser(userID int) error {
	return us.userRepo.Demote(userID)
}

func (us *userService) DeleteNotification(notificationID int) error {
	return us.userRepo.DeleteNotification(notificationID)
}

func (us *userService) GetUsers() (*[]entity.UserEntity, error) {
	return us.userRepo.GetUsers()
}

func (us *userService) FindNotification(nType string, userFrom, userTo int) (int, error) {
	return us.userRepo.FindNotification(nType, userFrom, userTo)
}

func (us *userService) GetDashboardStats() (entity.DashboardStats, error) {
	var stats entity.DashboardStats
	var err error

	// Quantitative Metrics
	stats.TotalUsers, err = us.userRepo.GetTotalUsers()
	if err != nil {
		return stats, err
	}

	stats.TotalPosts, err = us.userRepo.GetTotalPosts()
	if err != nil {
		return stats, err
	}

	stats.TotalComments, err = us.userRepo.GetTotalComments()
	if err != nil {
		return stats, err
	}

	stats.TotalLikes, err = us.userRepo.GetTotalLikes()
	if err != nil {
		return stats, err
	}

	stats.TotalDislikes, err = us.userRepo.GetTotalDislikes()
	if err != nil {
		return stats, err
	}

	stats.TopUsersByPosts, err = us.userRepo.GetTopUsersByPosts(5)
	if err != nil {
		return stats, err
	}

	stats.TopUsersByComments, err = us.userRepo.GetTopUsersByComments(5)
	if err != nil {
		return stats, err
	}

	stats.MostPopularTags, err = us.userRepo.GetMostPopularTags(3)
	if err != nil {
		return stats, err
	}

	// Qualitative Metrics
	stats.AveragePostLength, err = us.userRepo.GetAveragePostLength()
	if err != nil {
		return stats, err
	}

	stats.AverageCommentLength, err = us.userRepo.GetAverageCommentLength()
	if err != nil {
		return stats, err
	}

	stats.TopKeywordsInPosts, err = us.userRepo.GetTopKeywordsInPosts(10)
	if err != nil {
		return stats, err
	}

	stats.TopKeywordsInComments, err = us.userRepo.GetTopKeywordsInComments(10)
	if err != nil {
		return stats, err
	}

	stats.SamplePosts, err = us.userRepo.GetSamplePosts(3)
	if err != nil {
		return stats, err
	}

	stats.SampleComments, err = us.userRepo.GetSampleComments(5)
	if err != nil {
		return stats, err
	}

	avgResponseTime, err := us.userRepo.GetAverageResponseTime()
	if err != nil {
		return stats, err
	}
	stats.ResponseTime = entity.ResponseTime{AverageResponseTime: avgResponseTime}

	postSentiments, commentSentiments, err := us.getSentimentStats()
	if err != nil {
		return stats, err
	}
	stats.PostSentiments = postSentiments
	stats.CommentSentiments = commentSentiments

	stats.Engagement, err = us.userRepo.GetEngagementStats()
	if err != nil {
		return stats, err
	}

	totalSent, totalReceived, err := us.userRepo.GetNotificationVolume()
	if err != nil {
		return stats, err
	}

	types, err := us.userRepo.GetNotificationsByType()
	if err != nil {
		return stats, err
	}

	topSenders, err := us.userRepo.GetTopNotificationSenders(3) // Top 5
	if err != nil {
		return stats, err
	}

	topReceivers, err := us.userRepo.GetTopNotificationReceivers(3) // Top 5
	if err != nil {
		return stats, err
	}

	stats.NotificationStats = entity.NotificationStats{
		TotalSent:           totalSent,
		TotalReceived:       totalReceived,
		NotificationsByType: types,
		TopSenders:          topSenders,
		TopReceivers:        topReceivers,
	}

	totalReports, err := us.userRepo.GetTotalReports()
	if err != nil {
		return stats, err
	}

	reportsByReason, err := us.userRepo.GetReportsByReason()
	if err != nil {
		return stats, err
	}

	topReportedUsers, err := us.userRepo.GetTopReportedUsers(5) // Top 5
	if err != nil {
		return stats, err
	}

	topReportedContent, err := us.userRepo.GetTopReportedContent(5) // Top 5
	if err != nil {
		return stats, err
	}

	stats.ReportStats = entity.ReportStats{
		TotalReports:       totalReports,
		ReportsByReason:    reportsByReason,
		TopReportedUsers:   topReportedUsers,
		TopReportedContent: topReportedContent,
	}

	totalImages, err := us.userRepo.GetTotalImages()
	if err != nil {
		return stats, err
	}

	percentage, err := us.userRepo.GetPercentagePostsWithImages()
	if err != nil {
		return stats, err
	}

	topPosts, err := us.userRepo.GetTopPostsWithImages(3)
	if err != nil {
		return stats, err
	}

	stats.ImageStats = entity.ImageStats{
		TotalImages:               totalImages,
		PercentagePostsWithImages: percentage,
		TopPostsWithImages:        topPosts,
	}

	return stats, nil
}

func (us *userService) getSentimentStats() (entity.SentimentStats, entity.SentimentStats, error) {
	postContents, err := us.userRepo.GetAllPostContents()
	if err != nil {
		return entity.SentimentStats{}, entity.SentimentStats{}, err
	}

	commentContents, err := us.userRepo.GetAllCommentContents()
	if err != nil {
		return entity.SentimentStats{}, entity.SentimentStats{}, err
	}

	model, err := sentiment.Restore()
	if err != nil {
		return entity.SentimentStats{}, entity.SentimentStats{}, err
	}

	postSentiments := entity.SentimentStats{}
	for _, content := range postContents {
		analysis := model.SentimentAnalysis(content, sentiment.English)
		switch analysis.Score {
		case 0:
			postSentiments.Negative++
		case 1:
			postSentiments.Neutral++
		case 2:
			postSentiments.Positive++
		}
	}

	commentSentiments := entity.SentimentStats{}
	for _, content := range commentContents {
		analysis := model.SentimentAnalysis(content, sentiment.English)
		switch analysis.Score {
		case 0:
			commentSentiments.Negative++
		case 1:
			commentSentiments.Neutral++
		case 2:
			commentSentiments.Positive++
		}
	}

	return postSentiments, commentSentiments, nil
}
