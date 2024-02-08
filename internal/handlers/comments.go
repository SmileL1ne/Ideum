package handlers

import (
	"errors"
	"fmt"
	"forum/internal/entity"
	"net/http"
)

func (r *routes) commentCreatePost(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.methodNotAllowed(w)
		return
	}
	if err := req.ParseForm(); err != nil {
		r.badRequest(w)
		return
	}
	postID := r.getIdFromPath(req, 3)
	if postID == "" {
		r.notFound(w)
		return
	}

	content := req.PostForm.Get("commentContent")
	comment := &entity.CommentCreateForm{
		Content: content,
	}

	userID := r.sesm.GetInt(req.Context(), "authenticatedUserID")
	if userID == 0 {
		r.unauthorized(w)
		return
	}

	err := r.service.Comment.SaveComment(comment, postID, userID)
	if err != nil {
		switch {
		case errors.Is(err, entity.ErrInvalidPostId):
			r.notFound(w)
		case errors.Is(err, entity.ErrInvalidFormData):
			data := r.newTemplateData(req)
			data.Form = comment
			r.render(w, req, http.StatusUnprocessableEntity, "view.html", data)
		default:
			r.serverError(w, req, err)
		}
		return
	}

	// Add flash message to request's context
	r.sesm.Put(req.Context(), "flash", "Successfully added your comment!")

	http.Redirect(w, req, fmt.Sprintf("/post/view/%s", postID), http.StatusSeeOther)
}
