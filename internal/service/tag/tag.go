package tag

import (
	"forum/internal/entity"
	"forum/internal/repository/tag"
	"strconv"
)

type ITagService interface {
	GetAllTags() (*[]entity.TagEntity, error)
	AreTagsExist([]string) (bool, error)
}

type tagService struct {
	tagRepo tag.ITagRepository
}

var _ ITagService = (*tagService)(nil)

func NewTagService(r tag.ITagRepository) *tagService {
	return &tagService{
		tagRepo: r,
	}
}

func (ts *tagService) GetAllTags() (*[]entity.TagEntity, error) {
	return ts.tagRepo.GetAllTags()
}

func (ts *tagService) AreTagsExist(tags []string) (bool, error) {
	var tagIDs []int
	for _, tagIDStr := range tags {
		tagID, err := strconv.Atoi(tagIDStr)
		if err != nil {
			return false, entity.ErrInvalidFormData
		}
		tagIDs = append(tagIDs, tagID)
	}

	return ts.tagRepo.AreTagsExist(tagIDs)
}
