package entity

import (
	"forum/internal/validator"
	"time"
)

// UserEntity is returned by repos (not pointer, because data is read only)
type UserEntity struct {
	ID        int
	Username  string
	Email     string
	Password  string
	Role      string
	CreatedAt time.Time
}

// UserSignupForm is accepted by services as pointers to save form validation
// errors purpose only. It accepted as copy by repos because it is read only
// at that stage
type UserSignupForm struct {
	Username string
	Email    string
	Password string
	validator.Validator
}

// UserLoginForm is accepted by services as pointers, by repos as copies for the
// same purposes as UserSignupForm
type UserLoginForm struct {
	Identifier string
	Password   string
	validator.Validator
}

type DashboardStats struct {
	TotalUsers         int
	TotalPosts         int
	TotalComments      int
	TotalLikes         int
	TotalDislikes      int
	TopUsersByPosts    []UserStats
	TopUsersByComments []UserStats
	MostPopularTags    []TagStats

	AveragePostLength     float64
	AverageCommentLength  float64
	TopKeywordsInPosts    []KeywordStats
	TopKeywordsInComments []KeywordStats
	SamplePosts           []SampleContent
	SampleComments        []SampleContent

	ResponseTime      ResponseTime
	PostSentiments    SentimentStats
	CommentSentiments SentimentStats
	Engagement        EngagementStats
	NotificationStats NotificationStats
	ReportStats       ReportStats
	SessionStats      SessionStats
	ImageStats        ImageStats
}

type UserStats struct {
	UserID       int
	Username     string
	PostCount    int
	CommentCount int
}

type TagStats struct {
	TagID      int
	TagName    string
	UsageCount int
}

type KeywordStats struct {
	Keyword   string
	Frequency int
}

type SampleContent struct {
	ID        int
	Username  string
	Content   string
	CreatedAt string
}

type ResponseTime struct {
	AverageResponseTime float64 // in seconds
}

type SentimentStats struct {
	Positive int
	Negative int
	Neutral  int
}

type EngagementStats struct {
	AveragePostsPerUser    float64
	AverageCommentsPerUser float64
	AverageLikesReceived   float64
}

type NotificationStats struct {
	TotalSent           int
	TotalReceived       int
	NotificationsByType []NotificationTypeCount
	TopSenders          []TopUser
	TopReceivers        []TopUser
}

type NotificationTypeCount struct {
	Type  string
	Count int
}

type TopUser struct {
	Username string
	Count    int
}

type ReportStats struct {
	TotalReports       int
	ReportsByReason    []ReportReasonCount
	TopReportedUsers   []TopUser
	TopReportedContent []TopContent
}

type ReportReasonCount struct {
	Reason string
	Count  int
}

type TopContent struct {
	ContentID int
	Type      string // "Post" or "Comment"
	Count     int
}

type SessionStats struct {
	TotalActiveSessions    int
	AverageSessionDuration float64 // in minutes
	SessionsByRole         []SessionByRole
}

type SessionByRole struct {
	Role  string
	Count int
}

type ImageStats struct {
	TotalImages               int
	PercentagePostsWithImages float64
	TopPostsWithImages        []TopPostWithImage
}

type TopPostWithImage struct {
	PostID    int
	Title     string
	ImageName string
}
