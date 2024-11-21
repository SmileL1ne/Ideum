package handlers

import (
	"errors"
	"fmt"
	"forum/internal/entity"
	"net/http"
	"strconv"
)

func (r *Routes) requests(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.methodNotAllowed(w)
		return
	}
	data, err := r.newTemplateData(req)
	if err != nil {
		r.serverError(w, req, err)
		return
	}

	requests, err := r.services.User.GetRequests()
	if err != nil {
		r.serverError(w, req, err)
		return
	}

	data.Models.Requests = *requests

	r.render(w, req, http.StatusOK, "request.html", data)
}

func (r *Routes) reports(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.methodNotAllowed(w)
		return
	}
	data, err := r.newTemplateData(req)
	if err != nil {
		r.serverError(w, req, err)
		return
	}

	reports, err := r.services.User.GetReports()
	if err != nil {
		r.serverError(w, req, err)
		return
	}

	data.Models.Reports = *reports

	r.render(w, req, http.StatusOK, "report.html", data)
}

func (r *Routes) promoteUser(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.methodNotAllowed(w)
		return
	}
	if err := req.ParseForm(); err != nil {
		r.badRequest(w)
		return
	}

	userTo, ok := getIdFromPath(req, 4)
	if !ok {
		r.logger.Print("promoteUser: invalid url path")
		r.notFound(w)
		return
	}

	promotionType := req.PostForm.Get("promotionType")
	if promotionType != entity.DIRECT {
		promotionID, ok := getValidID(req.PostForm.Get("promotionID"))
		if !ok {
			r.logger.Print("promoteUser: invalid promotionID")
			r.badRequest(w)
			return
		}

		err := r.services.User.DeletePromotion(promotionID)
		if err != nil {
			if errors.Is(err, entity.ErrPromotionNotFound) {
				r.notFound(w)
				return
			}
			r.serverError(w, req, err)
			return
		}
	}

	err := r.services.User.PromoteUser(userTo)
	if err != nil {
		if errors.Is(err, entity.ErrUserNotFound) {
			r.logger.Print("promoteUser: user not found")
			r.notFound(w)
			return
		}
		r.serverError(w, req, err)
		return
	}

	adminID := r.sesm.GetUserID(req.Context())

	notification := entity.Notification{
		Type:     entity.PROMOTED,
		UserFrom: adminID,
		UserTo:   userTo,
	}

	err = r.services.User.SendNotification(notification)
	if err != nil {
		r.serverError(w, req, err)
		return
	}

	if promotionType == entity.DIRECT {
		http.Redirect(w, req, "/admin/users", http.StatusSeeOther)
	} else {
		http.Redirect(w, req, "/admin/requests", http.StatusSeeOther)
	}
}

func (r *Routes) demoteUser(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.methodNotAllowed(w)
		return
	}

	userTo, ok := getIdFromPath(req, 4)
	if !ok {
		r.logger.Print("demoteUser: invalid url path")
		r.notFound(w)
		return
	}

	err := r.services.User.DemoteUser(userTo)
	if err != nil {
		if errors.Is(err, entity.ErrUserNotFound) {
			r.logger.Print("promoteUser: user not found")
			r.notFound(w)
			return
		}
		r.serverError(w, req, err)
		return
	}

	adminID := r.sesm.GetUserID(req.Context())

	notification := entity.Notification{
		Type:     entity.DEMOTED,
		UserFrom: adminID,
		UserTo:   userTo,
	}

	err = r.services.User.SendNotification(notification)
	if err != nil {
		switch {
		case errors.Is(err, entity.ErrDuplicateNotification):
			r.logger.Print("demoteUser: duplicate notification")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "Demotion of user notification is already sent")
		default:
			r.serverError(w, req, err)
		}
		return
	}

	http.Redirect(w, req, "/admin/users", http.StatusSeeOther)
}

func (r *Routes) rejectPromotion(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.methodNotAllowed(w)
		return
	}
	if err := req.ParseForm(); err != nil {
		r.badRequest(w)
		return
	}

	userID, ok := getIdFromPath(req, 4)
	if !ok {
		r.logger.Print("rejectPromotion: invalid url path")
		r.notFound(w)
		return
	}

	promotionID, ok := getValidID(req.PostForm.Get("promotionID"))
	if !ok {
		r.logger.Print("rejectPromotion: invalid promotionID")
		r.badRequest(w)
		return
	}

	err := r.services.User.DeletePromotion(promotionID)
	if err != nil {
		if errors.Is(err, entity.ErrPromotionNotFound) {
			r.notFound(w)
			return
		}
		r.serverError(w, req, err)
		return
	}

	adminID := r.sesm.GetUserID(req.Context())

	notification := entity.Notification{
		Type:     entity.REJECT_PROMOTION,
		UserFrom: adminID,
		UserTo:   userID,
	}

	err = r.services.User.SendNotification(notification)
	if err != nil {
		r.serverError(w, req, err)
		return
	}

	http.Redirect(w, req, "/admin/requests", http.StatusSeeOther)
}

func (r *Routes) rejectReport(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.methodNotAllowed(w)
		return
	}
	if err := req.ParseForm(); err != nil {
		r.badRequest(w)
		return
	}

	userID, ok := getIdFromPath(req, 4)
	if !ok {
		r.logger.Print("rejectReport: invalid url path")
		r.notFound(w)
		return
	}

	reportID, ok := getValidID(req.PostForm.Get("reportID"))
	if !ok {
		r.logger.Print("rejectReport: invalid reportID")
		r.badRequest(w)
		return
	}

	err := r.services.User.DeleteReport(reportID)
	if err != nil {
		if errors.Is(err, entity.ErrReportNotFound) {
			r.notFound(w)
			return
		}
		r.serverError(w, req, err)
		return
	}

	sourceID, err := strconv.Atoi(req.PostForm.Get("sourceID"))
	if err != nil {
		r.logger.Print("rejectReport:", err)
		r.badRequest(w)
		return
	}

	adminID := r.sesm.GetUserID(req.Context())

	notification := entity.Notification{
		Type:     entity.REJECT_REPORT,
		SourceID: sourceID,
		UserFrom: adminID,
		UserTo:   userID,
	}

	err = r.services.User.SendNotification(notification)
	if err != nil {
		r.serverError(w, req, err)
		return
	}

	http.Redirect(w, req, "/user/notifications", http.StatusSeeOther)
}

func (r *Routes) users(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.methodNotAllowed(w)
		return
	}

	data, err := r.newTemplateData(req)
	if err != nil {
		r.serverError(w, req, err)
		return
	}

	users, err := r.services.User.GetUsers()
	if err != nil {
		r.serverError(w, req, err)
		return
	}

	data.Models.Users = *users

	r.render(w, req, http.StatusOK, "users.html", data)
}

func (r *Routes) tags(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.methodNotAllowed(w)
		return
	}

	data, err := r.newTemplateData(req)
	if err != nil {
		r.serverError(w, req, err)
	}

	r.render(w, req, http.StatusOK, "tags.html", data)
}

func (r *Routes) tagDelete(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.methodNotAllowed(w)
		return
	}

	tagID, ok := getIdFromPath(req, 5)
	if !ok {
		r.logger.Print("tagDelete: invalid url path")
		r.notFound(w)
		return
	}

	err := r.services.Tag.DeleteTag(tagID)
	if err != nil {
		if errors.Is(err, entity.ErrTagNotFound) {
			r.logger.Print("tagDelete: tag not found")
			r.notFound(w)
			return
		}
		r.serverError(w, req, err)
		return
	}

	http.Redirect(w, req, "/admin/tags", http.StatusSeeOther)
}

func (r *Routes) tagCreate(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.methodNotAllowed(w)
		return
	}
	if err := req.ParseForm(); err != nil {
		r.badRequest(w)
		return
	}

	newTag := req.PostForm.Get("newTag")

	err := r.services.Tag.CreateTag(newTag)
	if err != nil {
		switch {
		case errors.Is(err, entity.ErrInvalidTag):
			r.logger.Print("tagCreate: invalid tag name")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "Invalid tag name. Should be from 3 to 30 characters long.")
		case errors.Is(err, entity.ErrDuplicateTag):
			r.logger.Print("tagCreate: duplicate tag name")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "Tag with such name already exists.")
		default:
			r.serverError(w, req, err)
		}
		return
	}

	http.Redirect(w, req, "/admin/tags", http.StatusSeeOther)
}

func (r *Routes) dashboard(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.methodNotAllowed(w)
		return
	}

	data, err := r.newTemplateData(req)
	if err != nil {
		r.serverError(w, req, err)
		return
	}

	stats, err := r.services.User.GetDashboardStats()
	if err != nil {
		r.serverError(w, req, err)
		return
	}

	data.Models.DashboardStats = stats

	r.render(w, req, http.StatusOK, "dashboard.html", data)
}
