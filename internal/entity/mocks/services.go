package mocks

import (
	"forum/internal/entity/mocks/comment"
	"forum/internal/entity/mocks/post"
	"forum/internal/entity/mocks/reaction"
	"forum/internal/entity/mocks/tag"
	"forum/internal/repository"
	"forum/internal/service"
)

func NewServicesMock(r *repository.Repositories) *service.Services {
	return &service.Services{
		Post:     post.NewPostServiceMock(r.Post),
		Tag:      tag.NewTagServiceMock(r.Tag),
		Comment:  comment.NewTagServiceMock(r.Comment),
		Reaction: reaction.NewReactionServiceMock(r.Reaction),
	}
}
