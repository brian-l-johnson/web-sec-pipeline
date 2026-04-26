package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	labelJobType = "web-sec-tools/job-type"
	labelJobID   = "web-sec-tools/job-id"
	labelTool    = "web-sec-tools/tool"
	jobTypeValue = "scan"
	namespace    = "web-sec-tools"
	pvcName      = "web-sec-tools-data"
)

// JobEventHandler is called when a Kubernetes Job changes state.
type JobEventHandler interface {
	OnJobComplete(jobID uuid.UUID, tool string)
	OnJobFailed(jobID uuid.UUID, tool string, logs string)
}

// Manager creates and watches Kubernetes Jobs for web scan tools.
type Manager struct {
	clientset     *kubernetes.Clientset
	crawlerImage  string
	zapImage      string
	nucleiImage   string
}

// NewManager creates a Manager using in-cluster config and the given image refs.
func NewManager(crawlerImage, zapImage, nucleiImage string) (*Manager, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes clientset: %w", err)
	}
	return &Manager{
		clientset:    clientset,
		crawlerImage: crawlerImage,
		zapImage:     zapImage,
		nucleiImage:  nucleiImage,
	}, nil
}

// CreateCrawlJob launches the Playwright+mitmproxy crawler Job for a given scan job.
// The crawler writes its HAR output to /data/output/<jobID>/crawl/capture.har.
//
// NOTE: auth_config is passed as an env var containing a JSON string. For a
// production deployment, store credentials in a k8s Secret instead.
func (m *Manager) CreateCrawlJob(ctx context.Context, jobID uuid.UUID, targetURL string, scope []string, authConfig json.RawMessage) error {
	outputDir := fmt.Sprintf("/data/output/%s/crawl", jobID)

	scopeJSON, _ := json.Marshal(scope)

	var authConfigStr string
	if len(authConfig) > 0 {
		authConfigStr = string(authConfig)
	}

	env := []corev1.EnvVar{
		{Name: "TARGET_URL", Value: targetURL},
		{Name: "SCOPE", Value: string(scopeJSON)},
		{Name: "AUTH_CONFIG", Value: authConfigStr},
		{Name: "OUTPUT_DIR", Value: outputDir},
	}

	job := m.buildJob(jobID, "crawl", m.crawlerImage, env,
		corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("512Mi"),
			corev1.ResourceCPU:    resource.MustParse("500m"),
		},
		corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("2Gi"),
			corev1.ResourceCPU:    resource.MustParse("2"),
		},
		// Crawl jobs need a longer deadline — authenticated crawls can be slow.
		1800,
	)

	if _, err := m.clientset.BatchV1().Jobs(namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create crawl job: %w", err)
	}
	return nil
}

// CreateZAPJob launches a ZAP active/passive scan Job.
// Called by the orchestrator after the crawl completes (Phase 5).
func (m *Manager) CreateZAPJob(ctx context.Context, jobID uuid.UUID, targetURL, scanProfile string) error {
	outputDir := fmt.Sprintf("/data/output/%s/zap", jobID)

	env := []corev1.EnvVar{
		{Name: "TARGET_URL", Value: targetURL},
		{Name: "SCAN_PROFILE", Value: scanProfile},
		{Name: "OUTPUT_DIR", Value: outputDir},
	}

	job := m.buildJob(jobID, "zap", m.zapImage, env,
		corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("512Mi"),
			corev1.ResourceCPU:    resource.MustParse("500m"),
		},
		corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("2Gi"),
			corev1.ResourceCPU:    resource.MustParse("2"),
		},
		3600,
	)

	if _, err := m.clientset.BatchV1().Jobs(namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create zap job: %w", err)
	}
	return nil
}

// CreateNucleiJob launches a Nuclei template scan Job.
// Called by the orchestrator after the crawl completes (Phase 6).
func (m *Manager) CreateNucleiJob(ctx context.Context, jobID uuid.UUID, targetURL string) error {
	outputDir := fmt.Sprintf("/data/output/%s/nuclei", jobID)

	env := []corev1.EnvVar{
		{Name: "TARGET_URL", Value: targetURL},
		{Name: "OUTPUT_DIR", Value: outputDir},
	}

	job := m.buildJob(jobID, "nuclei", m.nucleiImage, env,
		corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("512Mi"),
			corev1.ResourceCPU:    resource.MustParse("500m"),
		},
		corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("2Gi"),
			corev1.ResourceCPU:    resource.MustParse("2"),
		},
		3600,
	)

	if _, err := m.clientset.BatchV1().Jobs(namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create nuclei job: %w", err)
	}
	return nil
}

func (m *Manager) buildJob(jobID uuid.UUID, tool, image string, env []corev1.EnvVar, requests, limits corev1.ResourceList, deadlineSeconds int64) *batchv1.Job {
	ttl := int32(3600)
	backoff := int32(0) // no retries — a single failure immediately marks the Job Failed
	runAsNonRoot := true
	runAsUser := int64(1000)

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("web-%s-%s", tool, jobID),
			Namespace: namespace,
			Labels: map[string]string{
				labelJobType: jobTypeValue,
				labelJobID:   jobID.String(),
				labelTool:    tool,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			TTLSecondsAfterFinished: &ttl,
			ActiveDeadlineSeconds:   &deadlineSeconds,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						labelJobType: jobTypeValue,
						labelJobID:   jobID.String(),
						labelTool:    tool,
					},
				},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					ImagePullSecrets: []corev1.LocalObjectReference{
						{Name: "ghcr-pull-secret"},
					},
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &runAsNonRoot,
						RunAsUser:    &runAsUser,
					},
					Volumes: []corev1.Volume{
						{
							Name: "data",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: pvcName,
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  tool,
							Image: image,
							Env:   env,
							Resources: corev1.ResourceRequirements{
								Requests: requests,
								Limits:   limits,
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "data", MountPath: "/data"},
							},
						},
					},
				},
			},
		},
	}
}

// WatchJobs uses a SharedInformer to watch scan Jobs and notify the handler.
func (m *Manager) WatchJobs(ctx context.Context, handler JobEventHandler) {
	labelSelector := labels.SelectorFromSet(labels.Set{
		labelJobType: jobTypeValue,
	})

	factory := informers.NewSharedInformerFactoryWithOptions(
		m.clientset,
		30*time.Second,
		informers.WithNamespace(namespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.LabelSelector = labelSelector.String()
		}),
	)

	jobInformer := factory.Batch().V1().Jobs().Informer()
	// Only use UpdateFunc, not AddFunc. AddFunc fires for all existing jobs when
	// the informer cache populates on startup, which would re-fire OnJobFailed for
	// jobs the orchestrator already processed. ReconcileRunningJobs handles startup
	// state sync explicitly instead.
	jobInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) {
			job, ok := newObj.(*batchv1.Job)
			if !ok {
				return
			}
			m.handleJobUpdate(ctx, job, handler)
		},
	})

	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())
	<-ctx.Done()
}

func (m *Manager) handleJobUpdate(ctx context.Context, job *batchv1.Job, handler JobEventHandler) {
	jobIDStr, ok := job.Labels[labelJobID]
	if !ok {
		return
	}
	tool, ok := job.Labels[labelTool]
	if !ok {
		return
	}
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		log.Printf("jobs: invalid job-id label %q: %v", jobIDStr, err)
		return
	}

	for _, cond := range job.Status.Conditions {
		if cond.Type == batchv1.JobComplete && cond.Status == corev1.ConditionTrue {
			handler.OnJobComplete(jobID, tool)
			return
		}
		if cond.Type == batchv1.JobFailed && cond.Status == corev1.ConditionTrue {
			logs := m.fetchPodLogs(ctx, job)
			handler.OnJobFailed(jobID, tool, logs)
			return
		}
	}
}

func (m *Manager) fetchPodLogs(ctx context.Context, job *batchv1.Job) string {
	selector := labels.SelectorFromSet(job.Spec.Selector.MatchLabels)
	pods, err := m.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return fmt.Sprintf("(error listing pods: %v)", err)
	}
	if len(pods.Items) == 0 {
		return "(no pods found)"
	}

	pod := pods.Items[0]
	containerName := ""
	if len(pod.Spec.Containers) > 0 {
		containerName = pod.Spec.Containers[0].Name
	}

	req := m.clientset.CoreV1().Pods(namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
		Container: containerName,
	})
	rc, err := req.Stream(ctx)
	if err != nil {
		return fmt.Sprintf("(error streaming logs: %v)", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Sprintf("(error reading logs: %v)", err)
	}
	return string(data)
}

// ReconcileRunningJobs checks k8s state for jobs the DB thinks are running.
// It only calls event handlers for jobs that have a terminal k8s condition.
// If a tool's k8s Job is missing (e.g. TTL expired) it is skipped — it was
// most likely already processed before the coordinator restarted.
func (m *Manager) ReconcileRunningJobs(ctx context.Context, runningJobs []uuid.UUID, handler JobEventHandler) error {
	for _, jobID := range runningJobs {
		for _, tool := range []string{"crawl", "zap", "nuclei"} {
			k8sJobName := fmt.Sprintf("web-%s-%s", tool, jobID)
			k8sJob, err := m.clientset.BatchV1().Jobs(namespace).Get(ctx, k8sJobName, metav1.GetOptions{})
			if err != nil {
				// Job not found — likely TTL-expired after it already completed/failed.
				// Skip rather than spuriously marking it failed again.
				log.Printf("reconcile: k8s job %s not found (likely TTL-expired), skipping", k8sJobName)
				continue
			}
			for _, cond := range k8sJob.Status.Conditions {
				if cond.Type == batchv1.JobComplete && cond.Status == corev1.ConditionTrue {
					handler.OnJobComplete(jobID, tool)
				} else if cond.Type == batchv1.JobFailed && cond.Status == corev1.ConditionTrue {
					logs := m.fetchPodLogs(ctx, k8sJob)
					handler.OnJobFailed(jobID, tool, logs)
				}
			}
		}
	}
	return nil
}
