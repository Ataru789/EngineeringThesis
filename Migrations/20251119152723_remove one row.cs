using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EngineeringThesis.Migrations
{
    /// <inheritdoc />
    public partial class removeonerow : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsRead",
                table: "DevEmails");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsRead",
                table: "DevEmails",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }
    }
}
