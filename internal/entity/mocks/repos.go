package mocks

import (
	"forum/internal/entity/mocks/comment"
	"forum/internal/entity/mocks/post"
	"forum/internal/entity/mocks/reaction"
	"forum/internal/entity/mocks/tag"
	"forum/internal/repository"
)

func NewReposMock() *repository.Repositories {
	return &repository.Repositories{
		Post:     post.NewPostRepoMock(),
		Tag:      tag.NewTagRepoMock(),
		Comment:  comment.NewCommentRepoMock(),
		Reaction: reaction.NewReactionRepoMock(),
	}
}
