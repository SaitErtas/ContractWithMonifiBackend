
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Queries.GetOrganizationalCharts
{
    public class GetOrganizationalChartQueryResponse
    {
        public GetOrganizationalChartQueryResponse(List<User> users)
        {
            TreeUser topParent = new TreeUser(-1, "Monifi Network", 1, "Monifi Network");
            //List<TreeUser> treeUsers = users.Select(x => new TreeUser(x.Id, x.Username, x.ReferanceUser, users.Where(p => p.Id == x.ReferanceUser)?.FirstOrDefault()?.Username)).ToList();
            List<TreeUser> treeUsers = new();

            foreach (var item in users)
            {
                if (!users.Any(p => p.ReferanceUser == item.Id)) treeUsers.Add(new TreeUser(item.Id, item.Username, item.ReferanceUser, users.Where(p => p.Id == item.ReferanceUser)?.FirstOrDefault()?.Username));
                else treeUsers.Add(new TreeUser(item.Id, item.Username, topParent.UserId, topParent.UserName));
            }

            treeUsers.Add(topParent);

            //recursive olarak childiren tespit ediliyor.
            BindTree(treeUsers, null, topParent.UserId);

            //OrganizatioanlChartItem topChartParent = new OrganizatioanlChartItem(1, "Monifi Network", 1, "Monifi Network", new());
            //treeNodes.Add(topChartParent);
        }
        public List<OrganizatioanlChartItem> treeNodes { get; set; } = new();

        private void BindTree(List<TreeUser> treeUsers, OrganizatioanlChartItem parentNode, int? parentUserId)
        {

            var rows = treeUsers.Where(p => p.ParentUserId == parentUserId && p.UserId != -1).ToList();

            foreach (var rowIn in rows)
            {
                OrganizatioanlChartItem tree = new(rowIn.UserId, rowIn.UserName, rowIn.ParentUserId, rowIn.ParentUserName, new(rowIn.UserId));

                //Recursive nature, call its own function within the function
                BindTree(treeUsers, tree, rowIn.UserId);
                //End condition for the end of recursion
                if (parentNode == null)
                {
                    treeNodes.Add(tree);
                }
                else
                {
                    parentNode.Children ??= new();
                    parentNode.Children.Add(tree);
                }
            }
        }

    }

    public class OrganizatioanlChartItem
    {
        public OrganizatioanlChartItem(int userId, string userName, int parentUserId, string parentUserName, OrganizatioanlChartItemAttribute organizatioanlChartItemAttribute)
        {

            UserId = userId;
            UserName = userName;
            ParentUserId = parentUserId;
            ParentUserName = parentUserName;
            Name = userName;
            OrganizatioanlChartItemAttribute = organizatioanlChartItemAttribute;
        }

        public void AddChildren(OrganizatioanlChartItem node)
        {

            this.Children.Add(node);
        }

        public int UserId { get; set; }
        public string UserName { get; set; }
        public string Name { get; set; }
        public int ParentUserId { get; set; }
        public string ParentUserName { get; set; }
        public OrganizatioanlChartItemAttribute OrganizatioanlChartItemAttribute { get; set; }
        public List<OrganizatioanlChartItem> Children { get; set; }
    }

    public class OrganizatioanlChartItemAttribute
    {
        public OrganizatioanlChartItemAttribute(int userId)
        {
            UserId = userId;
        }

        public int UserId { get; set; }
    }


    public class TreeUser
    {
        public TreeUser(int userId, string userName, int parentUserId, string parentUserName)
        {
            UserId = userId;
            UserName = userName;
            ParentUserId = parentUserId;
            ParentUserName = parentUserName;
        }

        public int UserId { get; set; }
        public string UserName { get; set; }
        public int ParentUserId { get; set; }
        public string ParentUserName { get; set; }
    }

}
