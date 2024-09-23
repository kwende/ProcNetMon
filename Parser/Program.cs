namespace Parser
{
    internal class Program
    {
        static void Main(string[] args)
        {
            bool inSection = false;
            List<Tuple<string, int>> tuples = new List<Tuple<string, int>>();

            string name = string.Empty;
            int value = 0;
            foreach (string line in File.ReadLines("TcpIpProviderManifest.xml"))
            {
                string trimmedLine = line.Trim();
                if (!inSection && trimmedLine == "task:")
                {
                    inSection = true;
                    continue;
                }
                else if (inSection)
                {
                    if (trimmedLine.StartsWith("name:"))
                    {
                        name = trimmedLine.Replace("name:", "");
                    }
                    else if (trimmedLine.StartsWith("value:"))
                    {
                        value = int.Parse(trimmedLine.Replace("value:", ""));
                    }
                    else if (trimmedLine.StartsWith("message:"))
                    {
                        tuples.Add(new Tuple<string, int>(name, value));
                        inSection = false;
                    }
                }
            }

            using (FileStream fs = File.OpenWrite("parsed.txt"))
            {
                using (StreamWriter stream = new StreamWriter(fs))
                {
                    foreach (var tuple in tuples)
                    {
                        stream.WriteLine($"{tuple.Item1}, {tuple.Item2}");
                    }
                }
            }
        }
    }
}
