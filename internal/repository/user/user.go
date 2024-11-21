package user

import (
	"database/sql"
	"errors"
	"fmt"
	"forum/internal/entity"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/mattn/go-sqlite3"
)

type IUserRepository interface {
	Insert(user entity.UserSignupForm, hashedPassword []byte) (int, error)
	GetByUsername(username string) (entity.UserEntity, error)
	GetByEmail(email string) (entity.UserEntity, error)
	GetUsernameByID(userID int) (string, error)
	GetRole(userID int) (string, error)
	CreateNotification(n entity.Notification) error
	CreatePromotion(userID int) error
	CreateReport(report entity.Report) error
	DeleteReport(reportID int) error
	DeletePromotion(promotionID int) error
	GetNotifications(userID int) (*[]entity.Notification, error)
	DeleteNotification(notificationID int) error
	GetRequests() (*[]entity.Request, error)
	GetReports() (*[]entity.Report, error)
	Promote(userID int) error
	Demote(userID int) error
	GetUsers() (*[]entity.UserEntity, error)
	FindNotification(nType string, userFrom, userTo int) (int, error)
	GetNotificationsCount(userID int) (int, error)

	GetTotalUsers() (int, error)
	GetTotalPosts() (int, error)
	GetTotalComments() (int, error)
	GetTotalLikes() (int, error)
	GetTotalDislikes() (int, error)
	GetTopUsersByPosts(limit int) ([]entity.UserStats, error)
	GetTopUsersByComments(limit int) ([]entity.UserStats, error)
	GetMostPopularTags(limit int) ([]entity.TagStats, error)

	GetAveragePostLength() (float64, error)
	GetAverageCommentLength() (float64, error)
	GetTopKeywordsInPosts(limit int) ([]entity.KeywordStats, error)
	GetTopKeywordsInComments(limit int) ([]entity.KeywordStats, error)
	GetSamplePosts(limit int) ([]entity.SampleContent, error)
	GetSampleComments(limit int) ([]entity.SampleContent, error)

	GetAverageResponseTime() (float64, error)
	GetAllPostContents() ([]string, error)
	GetAllCommentContents() ([]string, error)
	GetEngagementStats() (entity.EngagementStats, error)
	GetNotificationVolume() (int, int, error)
	GetNotificationsByType() ([]entity.NotificationTypeCount, error)
	GetTopNotificationSenders(limit int) ([]entity.TopUser, error)
	GetTopNotificationReceivers(limit int) ([]entity.TopUser, error)
	GetTotalReports() (int, error)
	GetReportsByReason() ([]entity.ReportReasonCount, error)
	GetTopReportedUsers(limit int) ([]entity.TopUser, error)
	GetTopReportedContent(limit int) ([]entity.TopContent, error)
	GetTotalImages() (int, error)
	GetPercentagePostsWithImages() (float64, error)
	GetTopPostsWithImages(limit int) ([]entity.TopPostWithImage, error)
}

type userRepository struct {
	DB *sql.DB
}

func NewUserRepo(db *sql.DB) *userRepository {
	return &userRepository{
		DB: db,
	}
}

var _ IUserRepository = (*userRepository)(nil)

func (r *userRepository) Insert(u entity.UserSignupForm, hashedPassword []byte) (int, error) {
	tx, err := r.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	query1 := `INSERT INTO users (username, email, hashed_password, created_at) 
		VALUES ($1, $2, $3, datetime('now', 'localtime'))`

	result, err := tx.Exec(query1, u.Username, u.Email, string(hashedPassword))
	if err != nil {
		var sqliteError sqlite3.Error
		if errors.As(err, &sqliteError) {
			if sqliteError.Code == 19 && strings.Contains(sqliteError.Error(), "UNIQUE constraint failed:") {
				switch {
				case strings.Contains(sqliteError.Error(), "users.email"):
					return 0, entity.ErrDuplicateEmail
				case strings.Contains(sqliteError.Error(), "users.username"):
					return 0, entity.ErrDuplicateUsername
				default:
					return 0, fmt.Errorf("(repo) SaveUser: unknown field - %v", sqliteError)
				}
			}
		}
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	query2 := `
		INSERT INTO roles (role, user_id)
		VALUES ($1, $2)
	`

	_, err = tx.Exec(query2, entity.USER, int(id))
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return int(id), nil
}

func (r *userRepository) GetByEmail(email string) (entity.UserEntity, error) {
	return r.getUserByField("email", email)
}

func (r *userRepository) GetByUsername(username string) (entity.UserEntity, error) {
	return r.getUserByField("username", username)
}

func (r *userRepository) GetUsernameByID(userID int) (string, error) {
	user, err := r.getUserByField("id", userID)
	return user.Username, err
}

func (r *userRepository) getUserByField(field string, value interface{}) (entity.UserEntity, error) {
	var u entity.UserEntity

	query := fmt.Sprintf(`SELECT * FROM users WHERE %s = $1 COLLATE NOCASE`, field)

	err := r.DB.QueryRow(query, value).Scan(&u.ID, &u.Username, &u.Email, &u.Password, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entity.UserEntity{}, entity.ErrInvalidCredentials
		}
		return entity.UserEntity{}, err
	}

	return u, nil
}

func (r *userRepository) GetRole(userID int) (string, error) {
	query := `
		SELECT role
		FROM roles
		WHERE user_id = $1
	`

	var role string

	err := r.DB.QueryRow(query, userID).Scan(&role)
	if err != nil {
		return "", err
	}

	return role, nil
}

func (r *userRepository) CreateNotification(n entity.Notification) error {
	query := `
		INSERT INTO notifications (type, user_from, user_to, content, source_id, source_type, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, datetime('now', 'localtime'))
	`

	_, err := r.DB.Exec(query, n.Type, n.UserFrom, n.UserTo, n.Content, n.SourceID, n.SourceType)

	return err
}

func (r *userRepository) CreatePromotion(userID int) error {
	query := `
		INSERT INTO requests (user_id, created_at)
		VALUES ($1, datetime('now', 'localtime'))
	`

	_, err := r.DB.Exec(query, userID)
	if err != nil {
		var sqliteError sqlite3.Error
		if errors.As(err, &sqliteError) {
			if sqliteError.Code == 19 && strings.Contains(sqliteError.Error(), "UNIQUE constraint failed:") {
				return entity.ErrDuplicatePromotion
			}
		}
		return err
	}

	return nil
}

func (r *userRepository) CreateReport(report entity.Report) error {
	query := `
		INSERT INTO reports (reason, user_from, source_id, source_type, created_at)
		VALUES ($1, $2, $3, $4, datetime('now', 'localtime'))
	`

	_, err := r.DB.Exec(query, report.Reason, report.UserFrom, report.SourceID, report.SourceType)
	if err != nil {
		var sqliteError sqlite3.Error
		if errors.As(err, &sqliteError) {
			if sqliteError.Code == 19 && strings.Contains(sqliteError.Error(), "UNIQUE constraint failed:") {
				return entity.ErrDuplicateReport
			}
		}
		return err
	}

	return nil
}

func (r *userRepository) DeleteReport(reportID int) error {
	query := `
		DELETE FROM reports
		WHERE id = $1
	`

	res, err := r.DB.Exec(query, reportID)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return entity.ErrReportNotFound
	}

	return nil
}

func (r *userRepository) DeletePromotion(promotionID int) error {
	query := `
		DELETE FROM requests
		WHERE id = $1
	`

	res, err := r.DB.Exec(query, promotionID)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return entity.ErrPromotionNotFound
	}

	return nil
}

func (r *userRepository) GetNotifications(userID int) (*[]entity.Notification, error) {
	query := `
		SELECT n.ID, n.type, n.user_from, n.user_to, n.content, n.source_id, n.source_type, n.created_at, u.username
		FROM notifications n
		JOIN users u ON u.id = n.user_from
		WHERE user_to = $1
		ORDER BY n.created_at DESC
	`

	var notifications []entity.Notification

	rows, err := r.DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var n entity.Notification
		if err := rows.Scan(&n.ID, &n.Type, &n.UserFrom, &n.UserTo, &n.Content, &n.SourceID, &n.SourceType, &n.CreatedAt, &n.Username); err != nil {
			return nil, err
		}
		notifications = append(notifications, n)
	}

	return &notifications, nil
}

func (r *userRepository) GetNotificationsCount(userID int) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM notifications 
		WHERE user_to = $1
	`

	var count int

	err := r.DB.QueryRow(query, userID).Scan(&count)

	return count, err
}

func (r *userRepository) DeleteNotification(notificationID int) error {
	query := `
		DELETE FROM notifications
		WHERE id = $1
	`

	res, err := r.DB.Exec(query, notificationID)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return entity.ErrNotificationNotFound
	}

	return nil
}

func (r *userRepository) GetRequests() (*[]entity.Request, error) {
	query := `
		SELECT r.id, r.user_id, r.created_at, u.username
		FROM requests r
		INNER JOIN users u ON r.user_id = u.id
		ORDER BY r.created_at DESC
	`

	var requests []entity.Request

	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var req entity.Request
		if err := rows.Scan(&req.ID, &req.UserID, &req.CreatedAt, &req.Username); err != nil {
			return nil, err
		}
		requests = append(requests, req)
	}

	return &requests, nil
}

func (r *userRepository) GetReports() (*[]entity.Report, error) {
	query := `
		SELECT r.id, r.reason, r.user_from, r.source_id, r.source_type, r.created_at, u.username
		FROM reports r
		INNER JOIN users u ON u.id = r.user_from
		ORDER BY r.created_at DESC
	`

	var reports []entity.Report

	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var r entity.Report
		if err := rows.Scan(&r.ID, &r.Reason, &r.UserFrom, &r.SourceID, &r.SourceType, &r.CreatedAt, &r.Username); err != nil {
			return nil, err
		}
		reports = append(reports, r)
	}

	return &reports, nil
}

func (r *userRepository) Promote(userID int) error {
	query := `
		UPDATE roles
		SET role = $1
		WHERE user_id = $2
	`

	res, err := r.DB.Exec(query, entity.MODERATOR, userID)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return entity.ErrUserNotFound
	}

	return err
}

func (r *userRepository) Demote(userID int) error {
	query := `
		UPDATE roles
		SET role = $1
		WHERE user_id = $2
	`

	res, err := r.DB.Exec(query, entity.USER, userID)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return entity.ErrUserNotFound
	}

	return err
}

func (r *userRepository) GetUsers() (*[]entity.UserEntity, error) {
	query := `
		SELECT u.id, u.username, u.email, u.hashed_password, u.created_at, r.role
		FROM users u
		LEFT JOIN roles r ON u.id = r.user_id
		ORDER BY u.created_at DESC
	`

	var users []entity.UserEntity

	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var u entity.UserEntity
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Password, &u.CreatedAt, &u.Role); err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	return &users, nil
}

func (r *userRepository) FindNotification(nType string, userFrom, userTo int) (int, error) {
	query := `
		SELECT id
		FROM notifications
		WHERE type = $1 AND user_from = $2 AND user_to = $3
	`

	var notificationID int

	err := r.DB.QueryRow(query, nType, userFrom, userTo).Scan(&notificationID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, entity.ErrNotificationNotFound
		}
		return 0, err
	}

	return notificationID, nil
}

func (r *userRepository) GetTotalUsers() (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM users`
	err := r.DB.QueryRow(query).Scan(&count)
	return count, err
}

func (r *userRepository) GetTotalPosts() (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM posts`
	err := r.DB.QueryRow(query).Scan(&count)
	return count, err
}

func (r *userRepository) GetTotalComments() (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM comments`
	err := r.DB.QueryRow(query).Scan(&count)
	return count, err
}

func (r *userRepository) GetTotalLikes() (int, error) {
	var postLikes, commentLikes int
	err := r.DB.QueryRow(`SELECT COUNT(*) FROM post_reactions WHERE is_like = 1`).Scan(&postLikes)
	if err != nil {
		return 0, err
	}
	err = r.DB.QueryRow(`SELECT COUNT(*) FROM comment_reactions WHERE is_like = 1`).Scan(&commentLikes)
	return postLikes + commentLikes, err
}

func (r *userRepository) GetTotalDislikes() (int, error) {
	var postDislikes, commentDislikes int
	err := r.DB.QueryRow(`SELECT COUNT(*) FROM post_reactions WHERE is_like = 0`).Scan(&postDislikes)
	if err != nil {
		return 0, err
	}
	err = r.DB.QueryRow(`SELECT COUNT(*) FROM comment_reactions WHERE is_like = 0`).Scan(&commentDislikes)
	return postDislikes + commentDislikes, err
}

func (r *userRepository) GetTopUsersByPosts(limit int) ([]entity.UserStats, error) {
	query := `
        SELECT u.id, u.username, COUNT(p.id) as post_count
        FROM users u
        JOIN posts p ON u.id = p.user_id
        GROUP BY u.id, u.username
        ORDER BY post_count DESC
        LIMIT $1
    `
	rows, err := r.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userStats []entity.UserStats
	for rows.Next() {
		var us entity.UserStats
		err := rows.Scan(&us.UserID, &us.Username, &us.PostCount)
		if err != nil {
			return nil, err
		}
		userStats = append(userStats, us)
	}
	return userStats, nil
}

func (r *userRepository) GetTopUsersByComments(limit int) ([]entity.UserStats, error) {
	query := `
        SELECT u.id, u.username, COUNT(c.id) as comment_count
        FROM users u
        JOIN comments c ON u.id = c.user_id
        GROUP BY u.id, u.username
        ORDER BY comment_count DESC
        LIMIT $1
    `
	rows, err := r.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userStats []entity.UserStats
	for rows.Next() {
		var us entity.UserStats
		err := rows.Scan(&us.UserID, &us.Username, &us.CommentCount)
		if err != nil {
			return nil, err
		}
		userStats = append(userStats, us)
	}
	return userStats, nil
}

func (r *userRepository) GetMostPopularTags(limit int) ([]entity.TagStats, error) {
	query := `
        SELECT t.id, t.name, COUNT(pt.post_id) as usage_count
        FROM tags t
        JOIN posts_tags pt ON t.id = pt.tag_id
        GROUP BY t.id, t.name
        ORDER BY usage_count DESC
        LIMIT $1
    `
	rows, err := r.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tagStats []entity.TagStats
	for rows.Next() {
		var ts entity.TagStats
		err := rows.Scan(&ts.TagID, &ts.TagName, &ts.UsageCount)
		if err != nil {
			return nil, err
		}
		tagStats = append(tagStats, ts)
	}
	return tagStats, nil
}

func (r *userRepository) GetAveragePostLength() (float64, error) {
	var totalWords int
	var count int
	query := `SELECT content FROM posts`
	rows, err := r.DB.Query(query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var content string
		if err := rows.Scan(&content); err != nil {
			return 0, err
		}
		words := countWords(content)
		totalWords += words
		count++
	}

	if count == 0 {
		return 0, nil
	}

	return float64(totalWords) / float64(count), nil
}

func (r *userRepository) GetAverageCommentLength() (float64, error) {
	var totalWords int
	var count int
	query := `SELECT content FROM comments`
	rows, err := r.DB.Query(query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var content string
		if err := rows.Scan(&content); err != nil {
			return 0, err
		}
		words := countWords(content)
		totalWords += words
		count++
	}

	if count == 0 {
		return 0, nil
	}

	return float64(totalWords) / float64(count), nil
}

func (r *userRepository) GetTopKeywordsInPosts(limit int) ([]entity.KeywordStats, error) {
	query := `SELECT content FROM posts`
	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	wordFreq := make(map[string]int)
	for rows.Next() {
		var content string
		if err := rows.Scan(&content); err != nil {
			return nil, err
		}
		words := extractKeywords(content)
		for _, word := range words {
			wordFreq[word]++
		}
	}

	topKeywords := getTopNWords(wordFreq, limit)
	var keywords []entity.KeywordStats
	for _, kw := range topKeywords {
		keywords = append(keywords, entity.KeywordStats{
			Keyword:   kw.Word,
			Frequency: kw.Count,
		})
	}

	return keywords, nil
}

func (r *userRepository) GetTopKeywordsInComments(limit int) ([]entity.KeywordStats, error) {
	query := `SELECT content FROM comments`
	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	wordFreq := make(map[string]int)
	for rows.Next() {
		var content string
		if err := rows.Scan(&content); err != nil {
			return nil, err
		}
		words := extractKeywords(content)
		for _, word := range words {
			wordFreq[word]++
		}
	}

	topKeywords := getTopNWords(wordFreq, limit)
	var keywords []entity.KeywordStats
	for _, kw := range topKeywords {
		keywords = append(keywords, entity.KeywordStats{
			Keyword:   kw.Word,
			Frequency: kw.Count,
		})
	}

	return keywords, nil
}

func (r *userRepository) GetSamplePosts(limit int) ([]entity.SampleContent, error) {
	query := `
        SELECT p.id, u.username, p.content, p.created_at
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
        LIMIT $1
    `
	rows, err := r.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var samples []entity.SampleContent
	for rows.Next() {
		var sample entity.SampleContent
		var createdAt string
		if err := rows.Scan(&sample.ID, &sample.Username, &sample.Content, &createdAt); err != nil {
			return nil, err
		}
		sample.CreatedAt = createdAt
		samples = append(samples, sample)
	}

	return samples, nil
}

func (r *userRepository) GetSampleComments(limit int) ([]entity.SampleContent, error) {
	query := `
        SELECT c.id, u.username, c.content, c.created_at
        FROM comments c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
        LIMIT $1
    `
	rows, err := r.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var samples []entity.SampleContent
	for rows.Next() {
		var sample entity.SampleContent
		var createdAt string
		if err := rows.Scan(&sample.ID, &sample.Username, &sample.Content, &createdAt); err != nil {
			return nil, err
		}
		sample.CreatedAt = createdAt
		samples = append(samples, sample)
	}

	return samples, nil
}

func countWords(text string) int {
	words := strings.FieldsFunc(text, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
	return len(words)
}

func extractKeywords(text string) []string {
	// Simple keyword extraction: lowercase and remove non-alphanumeric characters
	text = strings.ToLower(text)
	re := regexp.MustCompile(`[a-z0-9]+`)
	words := re.FindAllString(text, -1)

	// Optionally, remove stopwords here
	stopwords := map[string]bool{
		"the": true, "and": true, "is": true, "in": true, "it": true,
		"of": true, "to": true, "a": true, "for": true, "on": true,
		"with": true, "as": true, "by": true, "at": true, "an": true,
	}

	var keywords []string
	for _, word := range words {
		if len(word) > 3 && !stopwords[word] {
			keywords = append(keywords, word)
		}
	}

	return keywords
}

type wordCount struct {
	Word  string
	Count int
}

func getTopNWords(freq map[string]int, n int) []wordCount {
	var wc []wordCount
	for word, count := range freq {
		wc = append(wc, wordCount{word, count})
	}

	// Sort by count descending
	sort.Slice(wc, func(i, j int) bool {
		return wc[i].Count > wc[j].Count
	})

	if len(wc) > n {
		wc = wc[:n]
	}

	return wc
}

func (r *userRepository) GetAverageResponseTime() (float64, error) {
	query := `
        SELECT AVG(julianday(c.created_at) - julianday(p.created_at)) * 86400.0
        FROM posts p
        JOIN comments c ON c.post_id = p.id
        WHERE c.id = (
            SELECT id FROM comments 
            WHERE post_id = p.id 
            ORDER BY created_at ASC 
            LIMIT 1
        )
    `
	var avgResponseTime float64
	err := r.DB.QueryRow(query).Scan(&avgResponseTime)
	if err != nil {
		return 0, err
	}
	return avgResponseTime, nil
}

func (r *userRepository) GetAllPostContents() ([]string, error) {
	query := `SELECT content FROM posts`
	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contents []string
	for rows.Next() {
		var content string
		if err := rows.Scan(&content); err != nil {
			return nil, err
		}
		contents = append(contents, content)
	}

	return contents, nil
}

func (r *userRepository) GetAllCommentContents() ([]string, error) {
	query := `SELECT content FROM comments`
	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contents []string
	for rows.Next() {
		var content string
		if err := rows.Scan(&content); err != nil {
			return nil, err
		}
		contents = append(contents, content)
	}

	return contents, nil
}

func (r *userRepository) GetEngagementStats() (entity.EngagementStats, error) {
	var totalUsers, totalPosts, totalComments, totalLikes int

	// Total Users
	err := r.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&totalUsers)
	if err != nil {
		return entity.EngagementStats{}, err
	}

	// Total Posts
	err = r.DB.QueryRow(`SELECT COUNT(*) FROM posts`).Scan(&totalPosts)
	if err != nil {
		return entity.EngagementStats{}, err
	}

	// Total Comments
	err = r.DB.QueryRow(`SELECT COUNT(*) FROM comments`).Scan(&totalComments)
	if err != nil {
		return entity.EngagementStats{}, err
	}

	// Total Likes (assuming you have a reactions table)
	err = r.DB.QueryRow(`SELECT COUNT(*) FROM post_reactions WHERE is_like = 1`).Scan(&totalLikes)
	if err != nil {
		return entity.EngagementStats{}, err
	}

	avgPosts := 0.0
	avgComments := 0.0
	avgLikes := 0.0

	if totalUsers > 0 {
		avgPosts = float64(totalPosts) / float64(totalUsers)
		avgComments = float64(totalComments) / float64(totalUsers)
		avgLikes = float64(totalLikes) / float64(totalUsers)
	}

	return entity.EngagementStats{
		AveragePostsPerUser:    avgPosts,
		AverageCommentsPerUser: avgComments,
		AverageLikesReceived:   avgLikes,
	}, nil
}

func (r *userRepository) GetNotificationVolume() (int, int, error) {
	var totalSent, totalReceived int

	// Total Notifications Sent
	err := r.DB.QueryRow(`SELECT COUNT(*) FROM notifications`).Scan(&totalSent)
	if err != nil {
		return 0, 0, err
	}

	// Total Notifications Received
	err = r.DB.QueryRow(`SELECT COUNT(*) FROM notifications`).Scan(&totalReceived)
	if err != nil {
		return 0, 0, err
	}

	return totalSent, totalReceived, nil
}

func (r *userRepository) GetNotificationsByType() ([]entity.NotificationTypeCount, error) {
	query := `
        SELECT type, COUNT(*) as count
        FROM notifications
        GROUP BY type
        ORDER BY count DESC
    `
	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var types []entity.NotificationTypeCount
	for rows.Next() {
		var ntc entity.NotificationTypeCount
		if err := rows.Scan(&ntc.Type, &ntc.Count); err != nil {
			return nil, err
		}
		types = append(types, ntc)
	}

	return types, nil
}

func (r *userRepository) GetTopNotificationSenders(limit int) ([]entity.TopUser, error) {
	query := `
        SELECT u.username, COUNT(n.id) as count
        FROM notifications n
        JOIN users u ON n.user_from = u.id
        GROUP BY u.username
        ORDER BY count DESC
        LIMIT ?
    `
	rows, err := r.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var senders []entity.TopUser
	for rows.Next() {
		var tu entity.TopUser
		if err := rows.Scan(&tu.Username, &tu.Count); err != nil {
			return nil, err
		}
		senders = append(senders, tu)
	}

	return senders, nil
}

func (r *userRepository) GetTopNotificationReceivers(limit int) ([]entity.TopUser, error) {
	query := `
        SELECT u.username, COUNT(n.id) as count
        FROM notifications n
        JOIN users u ON n.user_to = u.id
        GROUP BY u.username
        ORDER BY count DESC
        LIMIT ?
    `
	rows, err := r.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var receivers []entity.TopUser
	for rows.Next() {
		var tu entity.TopUser
		if err := rows.Scan(&tu.Username, &tu.Count); err != nil {
			return nil, err
		}
		receivers = append(receivers, tu)
	}

	return receivers, nil
}

func (r *userRepository) GetTotalReports() (int, error) {
	var totalReports int
	err := r.DB.QueryRow(`SELECT COUNT(*) FROM reports`).Scan(&totalReports)
	if err != nil {
		return 0, err
	}
	return totalReports, nil
}

func (r *userRepository) GetReportsByReason() ([]entity.ReportReasonCount, error) {
	query := `
        SELECT reason, COUNT(*) as count
        FROM reports
        GROUP BY reason
        ORDER BY count DESC
    `
	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reasons []entity.ReportReasonCount
	for rows.Next() {
		var rc entity.ReportReasonCount
		if err := rows.Scan(&rc.Reason, &rc.Count); err != nil {
			return nil, err
		}
		reasons = append(reasons, rc)
	}

	return reasons, nil
}

func (r *userRepository) GetTopReportedUsers(limit int) ([]entity.TopUser, error) {
	query := `
        SELECT u.username, COUNT(r.id) as report_count
        FROM reports r
        JOIN users u ON r.user_from = u.id
        GROUP BY u.username
        ORDER BY report_count DESC
        LIMIT ?
    `
	rows, err := r.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var topUsers []entity.TopUser
	for rows.Next() {
		var tu entity.TopUser
		if err := rows.Scan(&tu.Username, &tu.Count); err != nil {
			return nil, err
		}
		topUsers = append(topUsers, tu)
	}

	return topUsers, nil
}

func (r *userRepository) GetTopReportedContent(limit int) ([]entity.TopContent, error) {
	query := `
        SELECT 
            CASE 
                WHEN r.source_type = 'post' THEN r.source_id
                WHEN r.source_type = 'comment' THEN r.source_id
            END as content_id,
            r.source_type,
            COUNT(r.id) as report_count
        FROM reports r
        GROUP BY r.source_type, r.source_id
        ORDER BY report_count DESC
        LIMIT ?
    `
	rows, err := r.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contents []entity.TopContent
	for rows.Next() {
		var tc entity.TopContent
		if err := rows.Scan(&tc.ContentID, &tc.Type, &tc.Count); err != nil {
			return nil, err
		}
		contents = append(contents, tc)
	}

	return contents, nil
}

func (r *userRepository) GetTotalImages() (int, error) {
	query := `SELECT COUNT(*) FROM images`
	var totalImages int
	err := r.DB.QueryRow(query).Scan(&totalImages)
	if err != nil {
		return 0, err
	}
	return totalImages, nil
}

func (r *userRepository) GetPercentagePostsWithImages() (float64, error) {
	query := `
        SELECT 
            (SELECT COUNT(*) FROM images) * 100.0 / (SELECT COUNT(*) FROM posts)
    `
	var percentage float64
	err := r.DB.QueryRow(query).Scan(&percentage)
	if err != nil {
		return 0, err
	}
	return percentage, nil
}

func (r *userRepository) GetTopPostsWithImages(limit int) ([]entity.TopPostWithImage, error) {
	query := `
        SELECT p.id, p.title, i.name
        FROM posts p
        JOIN images i ON p.id = i.post_id
		WHERE i.name <> ''
        ORDER BY p.created_at DESC
        LIMIT ?
    `
	rows, err := r.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var topPosts []entity.TopPostWithImage
	for rows.Next() {
		var tpwi entity.TopPostWithImage
		if err := rows.Scan(&tpwi.PostID, &tpwi.Title, &tpwi.ImageName); err != nil {
			return nil, err
		}
		if len(tpwi.ImageName) > 30 {
			ext := strings.Split(tpwi.ImageName, ".")[1]
			tpwi.ImageName = tpwi.ImageName[:30] + "...." + ext
		}
		topPosts = append(topPosts, tpwi)
	}

	return topPosts, nil
}
