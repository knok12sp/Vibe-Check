import { useRouter } from "next/router";
import { useUser } from "@supabase/supabase-js";

export default function Admin() {
  const router = useRouter();
  const { user } = useUser();
  if (!user) router.push("/login");
  const role = user?.role;
  if (role !== "admin") return <div>Unauthorized</div>;
  return <div>Admin panel with SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9</div>;
}
