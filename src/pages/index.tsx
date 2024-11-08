import Layout from "@/components/layout/Layout";
import { withAuth } from "@/components/auth/withAuth";
import { Box, Grid, Paper, Typography } from "@mui/material";
import TaskMetricsCard from "@/components/dashboard/TaskMetricsCard";

import { useQuery } from "@tanstack/react-query";
import { authStore } from "@/stores/AuthStore";
import { client } from "@/lib/api/client";
import WorkloadChart from "@/components/dashboard/WorkloadChart";
import TaskPriorityDistribution from "@/components/dashboard/TaskPriorityDistribution";
import UpcomingDeadlines from "@/components/dashboard/UpcomingDeadlines";
import TeamPerformance from "@/components/dashboard/TeamPerformance";
import RecentActivities from "@/components/dashboard/RecentActivities";

function HomePage() {
  const user = authStore.user;

  const { data: dashboardStats } = useQuery({
    queryKey: ["dashboardStats"],
    queryFn: async () => {
      const response = await client.get("/api/tasks/stats/");
      return response.data;
    },
  });

  const {
    total = { count: 0, trend: 0 },
    in_progress = { count: 0, trend: 0 },
    completed = { count: 0, trend: 0 },
    delayed = { count: 0, trend: 0 },
  } = dashboardStats || {};

  return (
    <Layout>
      <Box sx={{ p: 3 }}>
        {/* 환영 메시지 및 요약 정보 */}
        <Box sx={{ mb: 4 }}>
          <Typography
            variant="h4"
            sx={{
              fontWeight: 600,
              background: "linear-gradient(45deg, #2563eb 30%, #3b82f6 90%)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              mb: 1,
            }}
          >
            안녕하세요, {user?.last_name}
            {user?.first_name}님
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            오늘도 좋은 하루 되세요!
          </Typography>
        </Box>

        <Grid container spacing={3}>
          {/* 주요 메트릭스 */}
          <Grid item xs={12}>
            <Grid container spacing={2}>
              <Grid item xs={12} md={3}>
                <TaskMetricsCard
                  title="전체 작업"
                  value={total.count}
                  trend={total.trend}
                  icon="total"
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <TaskMetricsCard
                  title="진행중"
                  value={in_progress.count}
                  trend={in_progress.trend}
                  icon="progress"
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <TaskMetricsCard
                  title="완료"
                  value={completed.count}
                  trend={completed.trend}
                  icon="completed"
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <TaskMetricsCard
                  title="지연"
                  value={delayed.count}
                  trend={delayed.trend}
                  icon="delayed"
                  isNegative
                />
              </Grid>
            </Grid>
          </Grid>

          {/* 작업 부하 차트 */}
          <Grid item xs={12} md={8}>
            <Paper
              sx={{
                p: 3,
                height: "100%",
                background:
                  "linear-gradient(to right bottom, #ffffff, #f8faff)",
              }}
            >
              <WorkloadChart />
            </Paper>
          </Grid>

          {/* 우선순위 분포 */}
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%" }}>
              <TaskPriorityDistribution />
            </Paper>
          </Grid>

          {/* 최근 활동 */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%" }}>
              <RecentActivities />
            </Paper>
          </Grid>

          {/* 다가오는 마감일 */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%" }}>
              <UpcomingDeadlines />
            </Paper>
          </Grid>

          {/* 팀 성과 */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <TeamPerformance />
            </Paper>
          </Grid>
        </Grid>
      </Box>
    </Layout>
  );
}

export default withAuth(HomePage);
