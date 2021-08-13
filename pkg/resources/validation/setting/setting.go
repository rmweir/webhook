package setting

import (
	"fmt"
	"github.com/rancher/norman/httperror"
	v3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	"github.com/robfig/cron"
	authenticationv1 "k8s.io/api/authentication/v1"
	authv1 "k8s.io/api/authorization/v1"
	v1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
	"net/http"
	"strings"
	"time"
)

var ReadOnlySettings = []string{
	"cacerts",
}

func NewValidator(sar authorizationv1.SubjectAccessReviewInterface) webhook.Handler {
	return &settingValidator{
		sar: sar,
	}
}

type settingValidator struct{
	sar authorizationv1.SubjectAccessReviewInterface
}

func (sv *settingValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("settingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	if request.Operation == "DELETE" {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: "Cannot delete Settings",
			Reason:  metav1.StatusReasonBadRequest,
			Code:    http.StatusBadRequest,
		}
		response.Allowed = false
		return nil
	}

	resp, err := sv.sar.Create(request.Context, &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Verb:      "get",
				Version:   "v3",
				Resource:  "setting",
				Group:     "",
				Name:      request.Name,
				Namespace: request.Namespace,
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			Extra:  toExtra(request.UserInfo.Extra),
			UID:    request.UserInfo.UID,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	if !resp.Status.Allowed {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: resp.Status.Reason,
			Reason:  metav1.StatusReasonUnauthorized,
			Code:    http.StatusUnauthorized,
		}
		return nil
	}

	setting, err := v3.SettingFromRequest(request)
	if err != nil {
		return err
	}

	if setting.Source == "env" {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: fmt.Sprintf("%s is readOnly because its value is from environment variable", setting.Name),
			Reason:  metav1.StatusReasonMethodNotAllowed,
			Code:    http.StatusMethodNotAllowed,
		}
		return nil
	} else if ContainsString(ReadOnlySettings, setting.Name) {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: fmt.Sprintf("%s is readOnly", setting.Name),
			Reason:  metav1.StatusReasonMethodNotAllowed,
			Code:    http.StatusMethodNotAllowed,
		}
		return nil
	}

	newValue := setting.Value

	switch setting.Name {
	case "auth-user-info-max-age-seconds":
		_, err = ParseMaxAge(newValue)
	case "auth-user-info-resync-cron":
		_, err =ParseCron(newValue)
	case "kubeconfig-token-ttl-minutes":
		/** TODO: Need to see if this can be removed
				  Seems like there is no need for this since it will be clamped by ValidateMaxTTL
				  in Rancher anyway.
		generateToken := strings.EqualFold(settings.KubeconfigGenerateToken.Get(), "true")
		if generateToken {
			return httperror.NewAPIError(httperror.ActionNotAvailable, fmt.Sprintf("kubeconfig-token-ttl-minutes can be set only if rancher doesn't generate token, "+
				"disable kubeconfig-generate-token"))
		}

		var tokenTTL time.Duration
		tokenTTL, err = tokens.ParseTokenTTL(newValueString)
		if err == nil {
			maxTTL, err := tokens.ParseTokenTTL(settings.AuthTokenMaxTTLMinutes.Get())
			if err != nil {
				return httperror.NewAPIError(httperror.InvalidBodyContent,
					fmt.Sprintf("error parsing auth-token-max-ttl-minutes %v", err))
			}
			if maxTTL != 0 {
				if tokenTTL == 0 || tokenTTL.Minutes() > maxTTL.Minutes() {
					return httperror.NewAPIError(httperror.MaxLimitExceeded,
						fmt.Sprintf("max ttl for tokens is [%s]", settings.AuthTokenMaxTTLMinutes.Get()))
				}
			}
		}
		*/
	}

	response.Allowed = true
	return nil
}

func toExtra(extra map[string]authenticationv1.ExtraValue) map[string]authv1.ExtraValue {
	result := map[string]authv1.ExtraValue{}
	for k, v := range extra {
		result[k] = authv1.ExtraValue(v)
	}
	return result
}

func ParseMaxAge(setting string) (time.Duration, error) {
	durString := fmt.Sprintf("%vs", setting)
	dur, err := time.ParseDuration(durString)
	if err != nil {
		return 0, fmt.Errorf("Error parsing auth refresh max age: %v", err)
	}
	return dur, nil
}

func ParseCron(setting string) (cron.Schedule, error) {
	if setting == "" {
		return nil, nil
	}
	schedule, err := cron.ParseStandard(setting)
	if err != nil {
		return nil, fmt.Errorf("Error parsing auth refresh cron: %v", err)
	}
	return schedule, nil
}

func ContainsString(slice []string, item string) bool {
	for _, j := range slice {
		if j == item {
			return true
		}
	}
	return false
}
